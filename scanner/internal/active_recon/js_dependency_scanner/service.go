package js_dependency_scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/active_recon/js_dependency_scanner/scanner"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Service represents the JSDependencyScanner service
type Service struct {
	redis   *redis.Client
	logger  *zap.Logger
	scanner scanner.Scanner
}

// NewService creates a new JSDependencyScanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:   redisClient,
		logger:  logger,
		scanner: scanner.NewScanner(logger),
	}
}

// ProcessDiscovery processes a discovery target and scans for JS vulnerabilities
// Scans both HTTP and HTTPS protocols in parallel for maximum performance
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	s.logger.Info("Processing discovery for JSDependencyScanner",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Scan both HTTP and HTTPS in parallel
	allVulnerabilities := s.scanBothProtocols(ctx, target)

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
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding)
}

// convertToSecurityFinding converts a vulnerability to SecurityFinding format
func convertToSecurityFinding(vuln scanner.ProcessedVulnerability, pageURL string, target ScanTarget) shared.SecurityFinding {
	// Format title: "Component Version - Summary (CVEs)"
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

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Scanner:     "js_dependency_scanner",
		DiscoveryID: target.DiscoveryID,
		Severity:    vuln.Severity,
		Title:       title, // Full summary - no truncation
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}
}

// formatTitle formats the finding title: "Component Version - Summary (CVEs)"
func formatTitle(component, version, summary string, cves []string) string {
	var cveStr string
	if len(cves) > 0 {
		cveStr = fmt.Sprintf(" (%s)", strings.Join(cves, ", "))
	}

	// Capitalize component name
	component = strings.Title(component)

	// Full summary - no truncation
	return fmt.Sprintf("%s %s - %s%s", component, version, summary, cveStr)
}

// protocolScanResult holds the result of scanning a single protocol
type protocolScanResult struct {
	protocol        string
	url             string
	vulnerabilities []scanner.ProcessedVulnerability
}
