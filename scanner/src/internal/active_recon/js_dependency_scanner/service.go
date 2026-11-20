package js_dependency_scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/js_dependency_scanner/scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
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
	if ctx.Err() != nil {
		return ctx.Err() // shutdown: leave the trigger pending
	}

	// The check is complete only when every protocol answered (all its scripts checked) or
	// refused the connection.
	var probeErrs []error
	totalVulns := 0
	for _, result := range allVulnerabilities {
		probeErrs = append(probeErrs, result.err)
		totalVulns += len(result.vulnerabilities)
	}
	span.SetAttributes(attribute.Int("vulnerabilities.count", totalVulns))
	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	// Publish the findings, then the coverage that lists them. A failed publish is returned
	// before the coverage, so the consumer retries the target.
	reported, err := s.publishUniqueVulnerabilities(ctx, allVulnerabilities, target)
	if err != nil {
		return err
	}
	if probeErr := shared.ProbeError(probeErrs...); probeErr != nil {
		s.logger.Info("JS dependency check incomplete; its findings on this target stay open",
			zap.String("target", target.Target), zap.Error(probeErr))
		return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, nil, probeErr))
	}
	return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, reported, nil))
}

// scanBothProtocols scans both HTTP and HTTPS protocols concurrently and returns one result
// per protocol, with its error. A protocol can return vulnerabilities and an error (some
// scripts were not checked).
func (s *Service) scanBothProtocols(ctx context.Context, target ScanTarget) []protocolScanResult {
	protocols := []string{"http", "https"}
	results := make([]protocolScanResult, len(protocols))

	var wg sync.WaitGroup
	for i, proto := range protocols {
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := fmt.Sprintf("%s://%s", proto, target.Target)
			vulnerabilities, err := s.scanner.Scan(ctx, url)
			if err != nil {
				s.logger.Debug("Failed to scan URL", zap.String("url", url), zap.Error(err))
			}
			results[i] = protocolScanResult{protocol: proto, url: url, vulnerabilities: vulnerabilities, err: err}
		}()
	}
	wg.Wait()
	return results
}

// publishUniqueVulnerabilities publishes deduplicated vulnerabilities to Redis and returns
// their finding keys. It stops at the first failed publish.
func (s *Service) publishUniqueVulnerabilities(ctx context.Context, results []protocolScanResult, target ScanTarget) ([]shared.FindingKey, error) {
	// Dedup by component+version+CVE across all protocols
	seen := make(map[string]bool)
	var reported []shared.FindingKey

	for _, result := range results {
		for _, vuln := range result.vulnerabilities {
			// Create dedup key
			cveStr := strings.Join(vuln.CVEs, ",")
			if cveStr == "" {
				cveStr = "no-cve"
			}
			key := fmt.Sprintf("%s|%s|%s", vuln.Component, vuln.Version, cveStr)
			if seen[key] {
				continue
			}
			seen[key] = true

			finding := convertToSecurityFinding(vuln, result.url, target)
			if err := s.publishFinding(ctx, finding); err != nil {
				return nil, fmt.Errorf("publish JS finding %s %s: %w", vuln.Component, vuln.Version, err)
			}
			reported = append(reported, shared.FindingKey{FindingType: finding.FindingType, Title: finding.Title})

			s.logger.Info("Published vulnerability finding",
				zap.String("component", vuln.Component),
				zap.String("version", vuln.Version),
				zap.String("severity", vuln.Severity),
				zap.Strings("cves", vuln.CVEs),
				zap.String("org_id", target.OrgID),
			)
		}
	}
	return reported, nil
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
		Source:     findingSource,
		DiscoveryID: target.DiscoveryID,
		FindingType: findingType,
		Severity:    vuln.Severity,
		Title:       title,
		Description: vuln.Summary,
		References:  vuln.References,
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
// Strips markdown headers and truncates to ~120 chars on a word boundary.
func truncateSummary(summary string) string {
	if len(summary) <= maxTitleSummaryLength {
		return summary
	}

	// Strip markdown headers and everything after
	if idx := strings.Index(summary, "\n#"); idx > 0 {
		summary = strings.TrimSpace(summary[:idx])
	}

	// Clean up for single-line use
	summary = strings.TrimLeft(summary, "# ")
	summary = strings.ReplaceAll(summary, "\n", " ")

	if len(summary) <= maxTitleSummaryLength {
		return summary
	}

	// Truncate on word boundary
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
	err             error
}
