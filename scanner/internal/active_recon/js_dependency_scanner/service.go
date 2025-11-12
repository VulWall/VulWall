package js_dependency_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Service represents the JSDependencyScanner service
type Service struct {
	redis      *redis.Client
	logger     *zap.Logger
	httpClient *http.Client
}

// NewService creates a new JSDependencyScanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:      redisClient,
		logger:     logger,
		httpClient: createHTTPClient(),
	}
}

// ProcessDiscovery processes a discovery target and scans for JS vulnerabilities
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	s.logger.Info("Processing discovery for JSDependencyScanner",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Scan both HTTP and HTTPS
	protocols := []string{"http", "https"}
	allVulnerabilities := make(map[string]bool) // Dedup by component+version+CVE

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, target.Target)

		vulnerabilities, err := s.scanURL(ctx, url, target)
		if err != nil {
			s.logger.Debug("Failed to scan URL",
				zap.String("url", url),
				zap.Error(err),
			)
			continue
		}

		// Publish unique vulnerabilities
		for _, vuln := range vulnerabilities {
			// Create dedup key
			cveStr := strings.Join(vuln.CVEs, ",")
			if cveStr == "" {
				cveStr = "no-cve"
			}
			key := fmt.Sprintf("%s|%s|%s", vuln.Component, vuln.Version, cveStr)

			if !allVulnerabilities[key] {
				allVulnerabilities[key] = true

				// Convert to SecurityFinding and publish
				finding := s.convertToSecurityFinding(vuln, url, target)
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

	return nil
}

// scanURL scans a single URL for JS vulnerabilities
func (s *Service) scanURL(ctx context.Context, targetURL string, target ScanTarget) ([]ProcessedVulnerability, error) {
	// Step 1: Fetch HTML
	htmlContent, err := fetchHTML(ctx, targetURL, s.httpClient, s.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch HTML: %w", err)
	}

	// Step 2: Extract JS file URLs
	jsFiles := extractJSFiles(htmlContent, targetURL, s.logger)
	if len(jsFiles) == 0 {
		s.logger.Debug("No JavaScript files found", zap.String("url", targetURL))
		return nil, nil
	}

	s.logger.Debug("Found JavaScript files",
		zap.String("url", targetURL),
		zap.Int("count", len(jsFiles)),
	)

	// Step 3: Download JS files
	tmpDir, fileMetadata, err := downloadJSFiles(ctx, jsFiles, s.httpClient, s.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to download JS files: %w", err)
	}
	defer os.RemoveAll(tmpDir) // Clean up

	if len(fileMetadata) == 0 {
		s.logger.Debug("No JavaScript files downloaded successfully")
		return nil, nil
	}

	s.logger.Debug("Downloaded JavaScript files",
		zap.Int("count", len(fileMetadata)),
		zap.String("tmp_dir", tmpDir),
	)

	// Step 4: Run retire.js
	retireOutput, err := s.runRetireJS(ctx, tmpDir)
	if err != nil {
		// retire.js exits with code 13 when vulnerabilities found - this is expected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 13 {
			s.logger.Debug("Vulnerabilities detected by retire.js")
		} else {
			s.logger.Warn("retire.js execution error", zap.Error(err))
		}
	}

	// Step 5: Process vulnerabilities
	if retireOutput != nil && len(retireOutput.Data) > 0 {
		return s.processVulnerabilities(retireOutput, fileMetadata, targetURL), nil
	}

	return nil, nil
}

// runRetireJS executes retire.js CLI and parses output
func (s *Service) runRetireJS(ctx context.Context, scanPath string) (*RetireJSOutput, error) {
	// Run retire.js with JSON output
	cmd := exec.CommandContext(ctx, "retire",
		"--path", scanPath,
		"--outputformat", "json",
		"--nocache",
		"--severity", "low", // Report all severities
	)

	output, err := cmd.CombinedOutput()

	// Parse JSON output regardless of exit code
	var result RetireJSOutput
	if len(output) > 0 {
		if parseErr := json.Unmarshal(output, &result); parseErr != nil {
			return nil, fmt.Errorf("failed to parse retire.js output: %w (output: %s)", parseErr, string(output))
		}
	}

	return &result, err
}

// processVulnerabilities converts retire.js output to our format
func (s *Service) processVulnerabilities(retireOutput *RetireJSOutput, fileMetadata []JSFileMetadata, targetURL string) []ProcessedVulnerability {
	// Create filename to URL mapping
	filenameToURL := make(map[string]string)
	for _, meta := range fileMetadata {
		filenameToURL[meta.Filename] = meta.URL
	}

	var vulnerabilities []ProcessedVulnerability

	for _, fileData := range retireOutput.Data {
		// Extract original JS URL from filename
		filename := filepath.Base(fileData.File)
		jsURL := filenameToURL[filename]
		if jsURL == "" {
			jsURL = targetURL // Fallback to page URL
		}

		for _, result := range fileData.Results {
			for _, vuln := range result.Vulnerabilities {
				pv := ProcessedVulnerability{
					Component:        result.Component,
					Version:          result.Version,
					Severity:         vuln.Severity,
					Summary:          vuln.Identifiers.Summary,
					CVEs:             vuln.Identifiers.CVE,
					CWEs:             vuln.CWE,
					References:       vuln.Info,
					AffectedVersions: formatAffectedVersions(vuln.Below, vuln.AtOrAbove),
					JSURL:            jsURL,
					GitHubID:         vuln.Identifiers.GitHubID,
				}

				vulnerabilities = append(vulnerabilities, pv)
			}
		}
	}

	return vulnerabilities
}

// formatAffectedVersions formats the version range string
func formatAffectedVersions(below, atOrAbove string) string {
	var parts []string
	if atOrAbove != "" {
		parts = append(parts, fmt.Sprintf(">= %s", atOrAbove))
	}
	if below != "" {
		parts = append(parts, fmt.Sprintf("< %s", below))
	}
	return strings.Join(parts, " && ")
}

// convertToSecurityFinding converts a vulnerability to SecurityFinding format
func (s *Service) convertToSecurityFinding(vuln ProcessedVulnerability, pageURL string, target ScanTarget) shared.SecurityFinding {
	// Format title: "Component Version - Summary (CVEs)"
	title := formatTitle(vuln.Component, vuln.Version, vuln.Summary, vuln.CVEs)

	// Build metadata
	metadata := map[string]interface{}{
		"component":          vuln.Component,
		"version":            vuln.Version,
		"js_url":             vuln.JSURL,
		"page_url":           pageURL,
		"cves":               vuln.CVEs,
		"cwes":               vuln.CWEs,
		"affected_versions":  vuln.AffectedVersions,
		"references":         vuln.References,
		"detection_method":   "filecontent",
	}

	// Add optional GitHub ID if present
	if vuln.GitHubID != "" {
		metadata["github_id"] = vuln.GitHubID
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Source:      "js_dependency_scanner",
		DiscoveryID: target.DiscoveryID,
		FindingType: "",                // Empty per requirements
		Severity:    vuln.Severity,
		Title:       title,             // Full summary - no truncation
		Description: "",                // Empty per requirements
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

// publishFinding publishes a security finding to the Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding)
}

// ProcessedVulnerability represents a processed vulnerability ready for publishing
type ProcessedVulnerability struct {
	Component        string
	Version          string
	Severity         string
	Summary          string
	CVEs             []string
	CWEs             []string
	References       []string
	AffectedVersions string
	JSURL            string
	GitHubID         string
}
