package nikto_scanner

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

// Service handles Nikto web vulnerability scanning
type Service struct {
	redis  *redis.Client
	logger *zap.Logger
}

// NewService creates a new Nikto scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		logger: logger,
	}
}

// ProcessDiscovery scans a discovered asset with Nikto
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	s.logger.Info("Processing scan target",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Run Nikto scan
	findings, err := s.runNiktoScan(ctx, target.Target)
	if err != nil {
		s.logger.Error("Nikto scan failed",
			zap.String("target", target.Target),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Nikto scan completed",
		zap.String("target", target.Target),
		zap.Int("findings_count", len(findings)),
	)

	// Publish each finding to Redis
	for _, vuln := range findings {
		finding := s.convertToSecurityFinding(vuln, target)
		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish finding",
				zap.String("target", target.Target),
				zap.String("vuln_id", vuln.ID),
				zap.Error(err),
			)
			// Continue publishing other findings
		}
	}

	return nil
}

// runNiktoScan executes Nikto scanner on the target
func (s *Service) runNiktoScan(ctx context.Context, target string) ([]NiktoVuln, error) {
	// Build Nikto command
	// -h: target host
	// -Format json: JSON output format
	// -output -: output to stdout
	// -Tuning x: exclude informational tests (optional, remove if you want all)
	cmd := exec.CommandContext(ctx, "nikto.pl",
		"-h", target,
		"-Format", "json",
		"-output", "-",
	)

	// Execute command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Nikto may return non-zero exit codes even on successful scans
		if exitErr, ok := err.(*exec.ExitError); ok {
			s.logger.Debug("Nikto command stderr",
				zap.String("target", target),
				zap.Int("exit_code", exitErr.ExitCode()),
				zap.String("output", string(output)),
			)

			// If we got output, try to parse it anyway
			if len(output) > 0 {
				return s.parseNiktoOutput(output)
			}

			// No findings
			s.logger.Debug("Nikto found no vulnerabilities",
				zap.String("target", target),
			)
			return []NiktoVuln{}, nil
		}
		return nil, fmt.Errorf("nikto command failed: %w (output: %s)", err, string(output))
	}

	return s.parseNiktoOutput(output)
}

// parseNiktoOutput parses Nikto JSON output
func (s *Service) parseNiktoOutput(output []byte) ([]NiktoVuln, error) {
	// Nikto's JSON output is an array of scan results
	var niktoOutputs []NiktoOutput
	if err := json.Unmarshal(output, &niktoOutputs); err != nil {
		s.logger.Warn("Failed to parse Nikto JSON output",
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return nil, fmt.Errorf("failed to parse Nikto output: %w", err)
	}

	// Nikto returns an array, but we typically scan one target at a time
	// Collect all vulnerabilities from all results
	var allVulns []NiktoVuln
	for _, result := range niktoOutputs {
		allVulns = append(allVulns, result.Vulnerabilities...)
	}

	return allVulns, nil
}

// convertToSecurityFinding converts Nikto vulnerability to SecurityFinding model
func (s *Service) convertToSecurityFinding(vuln NiktoVuln, target ScanTarget) shared.SecurityFinding {
	// Determine severity based on OSVDB ID or description
	severity := s.determineSeverity(vuln)

	// Build metadata with all Nikto-specific data
	metadata := map[string]interface{}{
		"method":     vuln.Method,
		"url":        vuln.URL,
		"references": vuln.References,
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,      // Optional: scan identifier for linking to UI scans
		OrgID:       target.OrgID,
		Scanner:     "nikto",
		DiscoveryID: target.DiscoveryID,
		FindingType: vuln.ID, // Use Nikto test ID (e.g., "999986")
		Severity:    severity,
		Title:       vuln.Description,
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}
}

// determineSeverity attempts to determine severity from Nikto findings
func (s *Service) determineSeverity(vuln NiktoVuln) string {
	desc := strings.ToLower(vuln.Description)

	// Critical indicators
	if strings.Contains(desc, "remote code execution") ||
		strings.Contains(desc, "sql injection") ||
		strings.Contains(desc, "command injection") {
		return shared.SeverityCritical
	}

	// High severity indicators
	if strings.Contains(desc, "authentication bypass") ||
		strings.Contains(desc, "directory traversal") ||
		strings.Contains(desc, "arbitrary file") ||
		strings.Contains(desc, "cross-site scripting") ||
		strings.Contains(desc, "xss") {
		return shared.SeverityHigh
	}

	// Medium severity indicators
	if strings.Contains(desc, "information disclosure") ||
		strings.Contains(desc, "sensitive") ||
		strings.Contains(desc, "misconfiguration") ||
		strings.Contains(desc, "outdated") {
		return shared.SeverityMedium
	}

	// Low severity indicators
	if strings.Contains(desc, "missing header") ||
		strings.Contains(desc, "clickjacking") {
		return shared.SeverityLow
	}

	// Default to info for unknown/informational findings
	return shared.SeverityInfo
}

// publishFinding publishes a security finding to Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 20000)
}
