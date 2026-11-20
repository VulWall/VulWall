package testssl_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/VulWall/VulWall/scanner/src/internal/core/execx"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service handles testssl.sh TLS/SSL scanning
type Service struct {
	redis  *redis.Client
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new testssl scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		logger: logger,
		tracer: otel.Tracer("testssl-scanner"),
	}
}

// ProcessDiscovery scans a discovered asset with testssl.sh
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "testssl",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	s.logger.Info("Processing scan target",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Run testssl.sh scan (LOW severity and above - excludes INFO)
	findings, err := s.runTestSSLScan(ctx, target.Target, "LOW")
	if err != nil {
		s.logger.Error("testssl.sh scan failed",
			zap.String("target", target.Target),
			zap.Error(err),
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("scan.success", false))
		return err
	}

	span.SetAttributes(attribute.Int("findings.count", len(findings)))
	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	s.logger.Info("testssl.sh scan completed",
		zap.String("target", target.Target),
		zap.Int("findings_count", len(findings)),
	)

	// Publish each finding to Redis
	for _, testSSLFinding := range findings {
		finding := s.convertToSecurityFinding(testSSLFinding, target)
		// Skip findings downgraded to info by severity overrides (e.g. LUCKY13, SWEET32, CRIME_TLS)
		if strings.EqualFold(finding.Severity, shared.SeverityInfo) {
			continue
		}
		finding.TraceContext = telemetry.InjectTraceContext(ctx)
		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish finding",
				zap.String("target", target.Target),
				zap.String("finding_id", testSSLFinding.ID),
				zap.Error(err),
			)
			// Continue publishing other findings
		}
	}

	return nil
}

// resolveTargetIP resolves the host of a host:port target with the shared SSRF
// guard and returns the address testssl.sh must connect to.
func resolveTargetIP(ctx context.Context, target string) (string, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("invalid testssl target %q: %w", target, err)
	}
	ips, err := shared.ResolvePublicIPs(ctx, host)
	if err != nil {
		return "", err
	}
	return ips[0].String(), nil
}

// testSSLArgs builds the testssl.sh command line.
func testSSLArgs(jsonPath, severity, ip, target string) []string {
	return []string{
		"--jsonfile-pretty", jsonPath,
		"--quiet",
		"--warnings", "off",
		"-U",                   // Vulnerabilities only (BEAST, POODLE, Heartbleed, etc.)
		"--severity", severity, // Configurable minimum severity threshold
		"--ip", ip,
		target,
	}
}

// runTestSSLScan executes testssl.sh scanner on the target
func (s *Service) runTestSSLScan(ctx context.Context, target string, severity string) ([]TestSSLFinding, error) {
	// Create temporary file for JSON output
	// testssl.sh's --jsonfile writes to a file, not stdout
	tmpFile, err := os.CreateTemp("", "testssl-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath) // Clean up temp file

	// Build testssl.sh command
	// --jsonfile-pretty: output JSON to file (pretty format for readability)
	// --quiet: suppress banner and progress
	// --warnings off: don't show warnings
	// -U: scan for vulnerabilities only (not all checks)
	// --severity: filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
	// Target format: host:port
	// --ip: test the address we validated here instead of letting testssl.sh
	// resolve the host again (closes the DNS-rebinding window).
	ip, err := resolveTargetIP(ctx, target)
	if err != nil {
		return nil, err
	}
	cmd := execx.Command(ctx, "testssl.sh", testSSLArgs(tmpPath, severity, ip, target)...)

	// Execute command and capture stderr/stdout for error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// testssl.sh may return non-zero exit codes even on successful scans
		if exitErr, ok := err.(*exec.ExitError); ok {
			s.logger.Debug("testssl.sh command stderr",
				zap.String("target", target),
				zap.Int("exit_code", exitErr.ExitCode()),
				zap.String("output", string(output)),
			)

			// Exit codes 240-254 are fatal errors (connection issues, etc.)
			if exitErr.ExitCode() >= 240 {
				s.logger.Warn("testssl.sh fatal error",
					zap.String("target", target),
					zap.Int("exit_code", exitErr.ExitCode()),
				)
				// Return empty findings for fatal errors (target not reachable, etc.)
				return []TestSSLFinding{}, nil
			}

			// Try to read JSON file anyway - testssl.sh may have written findings
			if jsonData, readErr := os.ReadFile(tmpPath); readErr == nil && len(jsonData) > 0 {
				return s.parseTestSSLOutput(jsonData)
			}

			// No findings
			s.logger.Debug("testssl.sh found no issues",
				zap.String("target", target),
			)
			return []TestSSLFinding{}, nil
		}
		return nil, fmt.Errorf("testssl.sh command failed: %w (output: %s)", err, string(output))
	}

	// Read JSON output from temp file
	jsonData, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON output: %w", err)
	}

	return s.parseTestSSLOutput(jsonData)
}

// parseTestSSLOutput parses testssl.sh JSON output
func (s *Service) parseTestSSLOutput(output []byte) ([]TestSSLFinding, error) {
	// testssl.sh with --jsonfile-pretty outputs JSON with metadata + scanResult array
	// Format: { "Invocation": "...", "scanResult": [ { "vulnerabilities": [...], "headerResponse": [...] } ] }
	if len(output) == 0 {
		return []TestSSLFinding{}, nil
	}

	// Parse the full testssl.sh output structure
	var testsslOutput TestSSLOutput
	if err := json.Unmarshal(output, &testsslOutput); err != nil {
		s.logger.Warn("Failed to parse testssl.sh JSON output",
			zap.Error(err),
			zap.String("output_preview", string(output[:min(len(output), 500)])),
		)
		return nil, fmt.Errorf("failed to parse testssl.sh JSON: %w", err)
	}

	// Collect findings from all scan results
	var allFindings []TestSSLFinding
	for _, scanResult := range testsslOutput.ScanResult {
		// Extract vulnerabilities (BEAST, POODLE, Heartbleed, etc.)
		allFindings = append(allFindings, scanResult.Vulnerabilities...)

		// Extract HTTP header security issues (HSTS, missing headers, etc.)
		allFindings = append(allFindings, scanResult.HeaderResponse...)
	}

	// Filter findings: only include actual security issues
	var filteredFindings []TestSSLFinding
	for _, finding := range allFindings {
		// Skip non-security findings (case-insensitive)
		// We only want actual security issues: LOW, MEDIUM, HIGH, CRITICAL
		sev := strings.ToUpper(finding.Severity)
		if sev != "" && sev != "OK" && sev != "INFO" && sev != "WARN" && sev != "FATAL" {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	s.logger.Debug("Parsed testssl.sh findings",
		zap.Int("total_findings", len(allFindings)),
		zap.Int("security_issues", len(filteredFindings)),
	)

	return filteredFindings, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// convertToSecurityFinding converts testssl.sh finding to SecurityFinding model
func (s *Service) convertToSecurityFinding(testSSLFinding TestSSLFinding, target ScanTarget) shared.SecurityFinding {
	// Map testssl.sh severity to our severity constants
	severity := s.mapSeverity(testSSLFinding.Severity)

	// Apply finding-specific severity overrides
	if override, ok := severityOverrides[testSSLFinding.ID]; ok {
		severity = override
	}

	// Build metadata with all testssl.sh-specific data
	metadata := map[string]interface{}{
		"test_id": testSSLFinding.ID,
		"target":  target.Target, // e.g., "example.com:443"
	}

	if testSSLFinding.CWE != "" {
		metadata["cwe"] = testSSLFinding.CWE
	}
	if testSSLFinding.CVE != "" {
		metadata["cve"] = testSSLFinding.CVE
	}

	// Build title from test ID - make it descriptive
	title := fmt.Sprintf("TLS/SSL: %s", testSSLFinding.ID)
	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID, // Optional: scan identifier for linking to UI scans
		OrgID:       target.OrgID,
		Source:      "testssl",
		DiscoveryID: target.DiscoveryID,
		FindingType: testSSLFinding.ID, // Use test ID as finding type (e.g., "BREACH", "heartbleed")
		Severity:    severity,
		Title:       title,
		Description: testSSLFinding.Finding,
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}
}

// mapSeverity maps testssl.sh severity levels to our severity constants
func (s *Service) mapSeverity(testsslSeverity string) string {
	switch strings.ToUpper(testsslSeverity) {
	case "CRITICAL":
		return shared.SeverityCritical
	case "HIGH":
		return shared.SeverityHigh
	case "MEDIUM":
		return shared.SeverityMedium
	case "LOW":
		return shared.SeverityLow
	case "OK", "INFO":
		return shared.SeverityInfo
	default:
		return shared.SeverityInfo
	}
}

// publishFinding publishes a security finding to Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}
