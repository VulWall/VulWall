package testssl_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Service handles testssl.sh TLS/SSL scanning
type Service struct {
	redis  *redis.Client
	logger *zap.Logger
}

// NewService creates a new testssl scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		logger: logger,
	}
}

// ProcessDiscovery scans a discovered asset with testssl.sh
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	s.logger.Info("Processing scan target",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Run testssl.sh scan
	findings, err := s.runTestSSLScan(ctx, target.Target)
	if err != nil {
		s.logger.Error("testssl.sh scan failed",
			zap.String("target", target.Target),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("testssl.sh scan completed",
		zap.String("target", target.Target),
		zap.Int("findings_count", len(findings)),
	)

	// Publish each finding to Redis
	for _, testSSLFinding := range findings {
		finding := s.convertToSecurityFinding(testSSLFinding, target)
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

// runTestSSLScan executes testssl.sh scanner on the target
func (s *Service) runTestSSLScan(ctx context.Context, target string) ([]TestSSLFinding, error) {
	// Build testssl.sh command
	// --jsonfile -: output JSON to stdout
	// --quiet: suppress banner and progress
	// --warnings off: don't show warnings
	// Target format: host:port
	cmd := exec.CommandContext(ctx, "testssl.sh",
		"--jsonfile", "-",
		"--quiet",
		"--warnings", "off",
		target,
	)

	// Execute command and capture output
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

			// If we got output, try to parse it anyway
			if len(output) > 0 {
				return s.parseTestSSLOutput(output)
			}

			// No findings
			s.logger.Debug("testssl.sh found no issues",
				zap.String("target", target),
			)
			return []TestSSLFinding{}, nil
		}
		return nil, fmt.Errorf("testssl.sh command failed: %w (output: %s)", err, string(output))
	}

	return s.parseTestSSLOutput(output)
}

// parseTestSSLOutput parses testssl.sh JSON output
func (s *Service) parseTestSSLOutput(output []byte) ([]TestSSLFinding, error) {
	// testssl.sh outputs JSONL (JSON Lines) format - one JSON object per line
	// Each line can be a finding
	var allFindings []TestSSLFinding

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var finding TestSSLFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			s.logger.Debug("Failed to parse testssl.sh output line",
				zap.String("line", line),
				zap.Error(err),
			)
			continue
		}

		// Only include findings with severity (filter out info messages)
		if finding.Severity != "" && finding.Severity != "OK" {
			allFindings = append(allFindings, finding)
		}
	}

	return allFindings, nil
}

// convertToSecurityFinding converts testssl.sh finding to SecurityFinding model
func (s *Service) convertToSecurityFinding(testSSLFinding TestSSLFinding, target ScanTarget) shared.SecurityFinding {
	// Map testssl.sh severity to our severity constants
	severity := s.mapSeverity(testSSLFinding.Severity)

	// Build metadata with all testssl.sh-specific data
	metadata := map[string]interface{}{
		"test_id": testSSLFinding.ID,
		"ip":      testSSLFinding.IP,
		"port":    testSSLFinding.Port,
	}

	if testSSLFinding.CWE != "" {
		metadata["cwe"] = testSSLFinding.CWE
	}
	if testSSLFinding.CVE != "" {
		metadata["cve"] = testSSLFinding.CVE
	}

	// Build title from test ID and finding
	title := fmt.Sprintf("TLS/SSL: %s", testSSLFinding.ID)
	if len(title) > 100 {
		title = title[:97] + "..."
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		OrgID:       target.OrgID,
		Source:      "testssl",
		DiscoveryID: target.DiscoveryID,
		FindingType: testSSLFinding.ID, // Use test ID as finding type
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
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding)
}
