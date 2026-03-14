package js_dependency_scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/active_recon/js_dependency_scanner/scanner"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service represents the JSDependencyScanner service
type Service struct {
	redis   *redis.Client
	logger  *zap.Logger
	scanner scanner.Scanner
	tracer  trace.Tracer
}

// NewService creates a new JSDependencyScanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:   redisClient,
		logger:  logger,
		scanner: scanner.NewScanner(logger),
		tracer:  otel.Tracer("js-dependency-scanner"),
	}
}

// ProcessDiscovery processes a discovery target and scans for JS vulnerabilities
// Scans both HTTP and HTTPS protocols in parallel for maximum performance
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "jsscanner",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery for JSDependencyScanner",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Scan both HTTP and HTTPS in parallel
	allVulnerabilities := s.scanBothProtocols(ctx, target)

	// Count total vulnerabilities
	totalVulns := 0
	for _, result := range allVulnerabilities {
		totalVulns += len(result.vulnerabilities)
	}
	span.SetAttributes(attribute.Int("vulnerabilities.count", totalVulns))
	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	// Publish unique vulnerabilities to Redis
	s.publishUniqueVulnerabilities(ctx, allVulnerabilities, target)

	return nil
}

// scanBothProtocols scans both HTTP and HTTPS protocols concurrently
// Returns deduplicated vulnerabilities from both protocols
func (s *Service) scanBothProtocols(ctx context.Context, target ScanTarget) []protocolScanResult {
	protocols := []string{"http", "https"}
	results := make(chan protocolScanResult, len(protocols))

	var wg sync.WaitGroup

	// Launch parallel scans for each protocol
	for _, protocol := range protocols {
		wg.Add(1)
		go func(proto string) {
			defer wg.Done()

			url := fmt.Sprintf("%s://%s", proto, target.Target)
			vulnerabilities, err := s.scanner.Scan(ctx, url)

			if err != nil {
				s.logger.Debug("Failed to scan URL",
					zap.String("url", url),
					zap.Error(err),
				)
			}

			results <- protocolScanResult{
				protocol:        proto,
				url:             url,
				vulnerabilities: vulnerabilities,
			}
		}(protocol)
	}

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results from both protocols
	var allResults []protocolScanResult
	for result := range results {
		if len(result.vulnerabilities) > 0 {
			allResults = append(allResults, result)
		}
	}

	return allResults
}

// publishUniqueVulnerabilities publishes deduplicated vulnerabilities to Redis
func (s *Service) publishUniqueVulnerabilities(ctx context.Context, results []protocolScanResult, target ScanTarget) {
	// Dedup by component+version+CVE across all protocols
	seen := make(map[string]bool)

	for _, result := range results {
		for _, vuln := range result.vulnerabilities {
			// Create dedup key
			cveStr := strings.Join(vuln.CVEs, ",")
			if cveStr == "" {
				cveStr = "no-cve"
			}
			key := fmt.Sprintf("%s|%s|%s", vuln.Component, vuln.Version, cveStr)

			if !seen[key] {
				seen[key] = true

				// Convert to SecurityFinding and publish
				finding := convertToSecurityFinding(vuln, result.url, target)
				if err := s.publishFinding(ctx, finding); err != nil {
					s.logger.Error("Failed to publish finding",
						zap.String("component", vuln.Component),
						zap.String("version", vuln.Version),
						zap.Error(err),
					)
					continue
				}

				s.logger.Info("Published vulnerability finding",
					zap.String("component", vuln.Component),
					zap.String("version", vuln.Version),
					zap.String("severity", vuln.Severity),
					zap.Strings("cves", vuln.CVEs),
					zap.String("org_id", target.OrgID),
				)
			}
		}
	}
}

// publishFinding publishes a security finding to the Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	// Inject trace context for span linking across service boundaries
	finding.TraceContext = telemetry.InjectTraceContext(ctx)
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}

// convertToSecurityFinding converts a vulnerability to SecurityFinding format
func convertToSecurityFinding(vuln scanner.ProcessedVulnerability, pageURL string, target ScanTarget) shared.SecurityFinding {
	// Format title: "Component Version - Summary (CVEs)" with truncated summary
	title := formatTitle(vuln.Component, vuln.Version, vuln.Summary, vuln.CVEs)

	// Build metadata
	metadata := map[string]interface{}{
		"component":         vuln.Component,
		"version":           vuln.Version,
		"js_url":            vuln.JSURL,
		"page_url":          pageURL,
		"cves":              vuln.CVEs,
		"cwes":              vuln.CWEs,
		"affected_versions": vuln.AffectedVersions,
		"references":        vuln.References,
		"detection_method":  "filecontent",
	}

	// Preserve the full untruncated summary in metadata so no data is lost
	if len(vuln.Summary) > maxTitleSummaryLength {
		metadata["full_summary"] = vuln.Summary
	}

	// Add optional GitHub ID if present
	if vuln.GitHubID != "" {
		metadata["github_id"] = vuln.GitHubID
	}

	// Determine finding type: use primary CVE if available, otherwise use component-based identifier
	findingType := determineFindingType(vuln)

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Source:     "jsscanner",
		DiscoveryID: target.DiscoveryID,
		FindingType: findingType,
		Severity:    vuln.Severity,
		Title:       title,
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}
}

// determineFindingType creates a finding type identifier for the vulnerability
// Uses primary CVE if available, otherwise falls back to component-based identifier
func determineFindingType(vuln scanner.ProcessedVulnerability) string {
	// Use primary CVE if available (e.g., "CVE-2020-28458")
	if len(vuln.CVEs) > 0 {
		return strings.ToLower(vuln.CVEs[0])
	}

	// Fall back to component-based identifier (e.g., "js:jquery:prototype-pollution")
	// Sanitize component name for use as identifier
	component := strings.ToLower(vuln.Component)
	component = strings.ReplaceAll(component, " ", "-")

	return fmt.Sprintf("js:%s:vulnerability", component)
}

// maxTitleSummaryLength is the maximum character length for the summary portion of a finding title.
// Some retire.js advisories (e.g., GitHub Security Advisories) embed entire markdown documents
// in the summary field. We truncate to keep titles readable in Reports and Scans pages.
const maxTitleSummaryLength = 120

// formatTitle formats the finding title: "Component Version - Summary (CVEs)"
// The summary is truncated to the first sentence or ~120 chars to keep titles readable.
// If the summary contains markdown headers, only the text before the first header is used.
func formatTitle(component, version, summary string, cves []string) string {
	var cveStr string
	if len(cves) > 0 {
		cveStr = fmt.Sprintf(" (%s)", strings.Join(cves, ", "))
	}

	// Capitalize component name
	component = strings.Title(component)

	summary = truncateSummary(summary)

	return fmt.Sprintf("%s %s - %s%s", component, version, summary, cveStr)
}

// truncateSummary shortens a vulnerability summary for use in finding titles.
// It extracts the meaningful first sentence, stripping markdown headers and
// truncating at ~120 characters on a word boundary.
func truncateSummary(summary string) string {
	if summary == "" {
		return summary
	}

	// If the summary contains markdown headers, use only the text before the first one
	if idx := strings.Index(summary, "\n#"); idx > 0 {
		summary = strings.TrimSpace(summary[:idx])
	}

	// Strip any leading markdown header prefix (e.g., "# Title\n...")
	if strings.HasPrefix(summary, "#") {
		if newline := strings.IndexByte(summary, '\n'); newline > 0 {
			// Use the header text itself (without the # prefix) as the summary
			header := strings.TrimSpace(strings.TrimLeft(summary[:newline], "# "))
			rest := strings.TrimSpace(summary[newline+1:])
			if rest != "" {
				summary = header + " - " + rest
			} else {
				summary = header
			}
		} else {
			summary = strings.TrimSpace(strings.TrimLeft(summary, "# "))
		}
	}

	// Replace newlines with spaces for a clean single-line title
	summary = strings.ReplaceAll(summary, "\n", " ")

	// Already short enough — return as-is
	if len(summary) <= maxTitleSummaryLength {
		return summary
	}

	// Try to truncate at the first sentence boundary within the limit
	for _, sep := range []string{". ", ".\t"} {
		if idx := strings.Index(summary, sep); idx > 0 && idx <= maxTitleSummaryLength {
			return summary[:idx+1]
		}
	}

	// No sentence boundary found — truncate on a word boundary
	truncated := summary[:maxTitleSummaryLength]
	if lastSpace := strings.LastIndexByte(truncated, ' '); lastSpace > 0 {
		truncated = truncated[:lastSpace]
	}

	return truncated + "..."
}

// protocolScanResult holds the result of scanning a single protocol
type protocolScanResult struct {
	protocol        string
	url             string
	vulnerabilities []scanner.ProcessedVulnerability
}
