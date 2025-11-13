package nuclei_scanner

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

// Service handles Nuclei vulnerability scanning
type Service struct {
	redis  *redis.Client
	logger *zap.Logger
}

// NewService creates a new Nuclei scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		logger: logger,
	}
}

// ProcessDiscovery scans a discovered asset with Nuclei
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	s.logger.Info("Processing scan target",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Run Nuclei scan
	findings, err := s.runNucleiScan(ctx, target.Target, "low,medium,high,critical")
	if err != nil {
		s.logger.Error("Nuclei scan failed",
			zap.String("target", target.Target),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Nuclei scan completed",
		zap.String("target", target.Target),
		zap.Int("findings_count", len(findings)),
	)

	// Publish each finding to Redis
	for _, nucleiOutput := range findings {
		finding := s.convertToSecurityFinding(nucleiOutput, target)
		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish finding",
				zap.String("target", target.Target),
				zap.String("template_id", nucleiOutput.TemplateID),
				zap.Error(err),
			)
			// Continue publishing other findings
		}
	}

	return nil
}

// runNucleiScan executes Nuclei scanner on the target
func (s *Service) runNucleiScan(ctx context.Context, target, severity string) ([]NucleiOutput, error) {
	// Build Nuclei command
	// -u: target URL
	// -j: JSONL output (one JSON per line)
	// -silent: suppress banner and update check
	cmd := exec.CommandContext(ctx, "nuclei",
		"-u", target,
		"-j",
		"-silent",
		"-severity", severity,
	)

	// Execute command and capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's a context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Nuclei returns exit code 1 when no findings, which is not an error
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Log the stderr output for debugging
			s.logger.Debug("Nuclei command stderr",
				zap.String("target", target),
				zap.Int("exit_code", exitErr.ExitCode()),
				zap.String("output", string(output)),
			)

			if exitErr.ExitCode() == 1 && len(output) == 0 {
				s.logger.Debug("Nuclei found no vulnerabilities",
					zap.String("target", target),
				)
				return []NucleiOutput{}, nil
			}
		}
		return nil, fmt.Errorf("nuclei command failed: %w (output: %s)", err, string(output))
	}

	// Parse Nuclei JSON output (JSONL format - one JSON per line)
	var findings []NucleiOutput
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var nucleiOutput NucleiOutput
		if err := json.Unmarshal([]byte(line), &nucleiOutput); err != nil {
			s.logger.Warn("Failed to parse Nuclei output line",
				zap.String("line", line),
				zap.Error(err),
			)
			continue
		}

		findings = append(findings, nucleiOutput)
	}

	return findings, nil
}

// convertToSecurityFinding converts Nuclei output to SecurityFinding model
func (s *Service) convertToSecurityFinding(nucleiOutput NucleiOutput, target ScanTarget) shared.SecurityFinding {
	// Map Nuclei severity to our severity constants
	severity := s.mapSeverity(nucleiOutput.Info.Severity)

	// Build metadata with all Nuclei-specific data
	metadata := map[string]interface{}{
		"template_id":       nucleiOutput.TemplateID,
		"template_path":     nucleiOutput.TemplatePath,
		"type":              nucleiOutput.Type,
		"matched_at":        nucleiOutput.MatchedAt,
		"matcher_name":      nucleiOutput.MatcherName,
		"curl_command":      nucleiOutput.CurlCommand,
		"extracted_results": nucleiOutput.ExtractedResults,
		"author":            nucleiOutput.Info.Author,
		"tags":              nucleiOutput.Info.Tags,
		"reference":         nucleiOutput.Info.Reference,
	}

	// Merge Nuclei metadata if present
	if nucleiOutput.Info.Metadata != nil {
		metadata["nuclei_metadata"] = nucleiOutput.Info.Metadata
	}
	if nucleiOutput.Metadata != nil {
		for k, v := range nucleiOutput.Metadata {
			metadata[k] = v
		}
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,  // Pass through scan_id
		OrgID:       target.OrgID,
		Scanner:     "nuclei",
		DiscoveryID: target.DiscoveryID,
		FindingType: nucleiOutput.TemplateID,
		Severity:    severity,
		Title:       nucleiOutput.Info.Name,
		Description: nucleiOutput.Info.Description,
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}
}

// mapSeverity maps Nuclei severity levels to our severity constants
func (s *Service) mapSeverity(nucleiSeverity string) string {
	switch strings.ToLower(nucleiSeverity) {
	case "info", "informational":
		return shared.SeverityInfo
	case "low":
		return shared.SeverityLow
	case "medium":
		return shared.SeverityMedium
	case "high":
		return shared.SeverityHigh
	case "critical":
		return shared.SeverityCritical
	default:
		return shared.SeverityInfo
	}
}

// publishFinding publishes a security finding to Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding)
}
