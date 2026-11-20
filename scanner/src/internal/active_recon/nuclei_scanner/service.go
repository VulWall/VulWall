package nuclei_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
	"github.com/VulWall/VulWall/scanner/src/internal/core/audit"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service handles Nuclei vulnerability scanning
type Service struct {
	redis       *redis.Client
	logger      *zap.Logger
	tracer      trace.Tracer
	auditLogger *audit.Logger
	cron        *cron.Cron
}

// NewService creates a new Nuclei scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:       redisClient,
		logger:      logger,
		tracer:      otel.Tracer("nuclei-scanner"),
		auditLogger: audit.NewLogger(redisClient, logger, "nuclei-scanner"),
	}
}

// StartTemplateUpdater starts a cron job for periodic Nuclei template updates
// The schedule can be overridden via NUCLEI_TEMPLATE_UPDATE_CRON environment variable
func (s *Service) StartTemplateUpdater(ctx context.Context) {
	// Get cron schedule from environment or use default
	cronSchedule := config.GetEnv(config.EnvNucleiTemplateUpdateCron, DefaultTemplateUpdateCron)

	s.logger.Info("Starting Nuclei template updater",
		zap.String("schedule", cronSchedule),
	)

	// Run update immediately on startup to ensure templates are current
	s.updateTemplates(ctx)

	// Create cron scheduler
	s.cron = cron.New()

	// Add the template update job
	_, err := s.cron.AddFunc(cronSchedule, func() {
		s.updateTemplates(ctx)
	})
	if err != nil {
		s.logger.Error("Failed to schedule template update cron job",
			zap.String("schedule", cronSchedule),
			zap.Error(err),
		)
		return
	}

	// Start the cron scheduler
	s.cron.Start()

	// Wait for context cancellation to stop
	go func() {
		<-ctx.Done()
		s.logger.Info("Stopping template updater")
		s.cron.Stop()
	}()
}

// updateTemplates runs nuclei -update-templates and publishes audit log
func (s *Service) updateTemplates(ctx context.Context) {
	ctx, span := s.tracer.Start(ctx, "update_templates")
	defer span.End()

	// Only one replica updates the shared templates volume per tick; others skip.
	host, hostErr := os.Hostname() // lock owner — for debugging and ownership-checked release
	if hostErr != nil || host == "" {
		host = uuid.NewString() // ensure a unique, non-empty owner value
	}
	acquired, err := redisx.TryAcquireLock(ctx, s.redis, TemplateUpdateLockKey, host, TemplateUpdateLockTTL)
	if err != nil {
		// redis unreachable -> skip update (no coordination possible; scans are down too).
		// Templates on the shared volume stay usable.
		s.logger.Warn("Could not acquire template-update lock, skipping", zap.Error(err))
		return
	}
	if !acquired {
		s.logger.Info("Another replica is updating templates, skipping")
		return
	}
	defer redisx.ReleaseLock(ctx, s.redis, TemplateUpdateLockKey, host)

	s.logger.Info("Checking for Nuclei template updates...")

	// Get version before update
	versionBefore := s.getTemplateVersion(ctx)

	// Run update with 5-minute timeout
	updateCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(updateCtx, "nuclei", "-update-templates")
	output, err := cmd.CombinedOutput()

	// Get version after update
	versionAfter := s.getTemplateVersion(ctx)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}

	// Log audit event using shared audit logger
	s.auditLogger.LogOperation(ctx,
		"TemplateUpdate",
		"Nuclei templates updated",
		"Nuclei template update failed",
		err,
		map[string]any{
			"version_before": versionBefore,
			"version_after":  versionAfter,
			"output":         string(output),
		},
	)
}

// getTemplateVersion returns current Nuclei template version
func (s *Service) getTemplateVersion(ctx context.Context) string {
	// Bound this probe so a hung `nuclei -tv` can't push the lock-held time past
	// TemplateUpdateLockTTL (keeps the TTL-vs-update-timeout invariant true).
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nuclei", "-tv")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// ProcessDiscovery scans a discovered asset with Nuclei
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "nuclei",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	includeTags := getTagEnv(config.EnvNucleiIncludeTags, DefaultIncludeTags)
	excludeTags := getTagEnv(config.EnvNucleiExcludeTags, DefaultExcludeTags)

	s.logger.Info("Processing scan target",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
		zap.String("include_tags", includeTags),
		zap.String("exclude_tags", excludeTags),
	)

	// Run Nuclei scan
	findings, err := s.runNucleiScan(ctx, target.Target, "low,medium,high,critical")
	if err != nil {
		s.logger.Error("Nuclei scan failed",
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

// nucleiArgs builds the nuclei command line for one target.
func nucleiArgs(target, severity string) []string {
	args := []string{
		"-u", target,
		"-t", "/root/nuclei-templates",
		"-j",
		"-silent",
		"-severity", severity,
	}

	// -lna (restrict-local-network-access) makes nuclei refuse connections to
	// local/private networks at dial time, which also covers DNS rebinding
	// between discovery and scan. Skipped when private targets are allowed.
	if !shared.PrivateTargetsAllowed() {
		args = append(args, "-lna")
	}

	// Append tag filters only when non-empty
	includeTags := getTagEnv(config.EnvNucleiIncludeTags, DefaultIncludeTags)
	if includeTags != "" {
		args = append(args, "-tags", includeTags)
	}
	excludeTags := getTagEnv(config.EnvNucleiExcludeTags, DefaultExcludeTags)
	if excludeTags != "" {
		args = append(args, "-etags", excludeTags)
	}

	return args
}

// runNucleiScan executes Nuclei scanner on the target
func (s *Service) runNucleiScan(ctx context.Context, target, severity string) ([]NucleiOutput, error) {
	cmd := exec.CommandContext(ctx, "nuclei", nucleiArgs(target, severity)...)

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

	// Apply template-specific severity overrides
	if override, ok := severityOverrides[nucleiOutput.TemplateID]; ok {
		severity = override
	}

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
		Source:     "nuclei",
		DiscoveryID: target.DiscoveryID,
		FindingType: nucleiOutput.TemplateID,
		Severity:    severity,
		Title:       nucleiOutput.Info.Name,
		Description: nucleiOutput.Info.Description,
		Remediation: nucleiOutput.Info.Remediation,
		References:  nucleiOutput.Info.Reference,
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

// getTagEnv retrieves Nuclei tag configuration with empty-string-aware semantics.
// Uses os.LookupEnv instead of config.GetEnv because config.GetEnv treats "" and
// unset identically. For Nuclei tags the distinction matters:
//   - Unset       → use opinionated defaults (DefaultIncludeTags/DefaultExcludeTags)
//   - Set to ""   → disable the filter (omit the CLI flag, run all templates)
//   - Set to val  → use the custom value
func getTagEnv(envKey, defaultValue string) string {
	if val, ok := os.LookupEnv(envKey); ok {
		return val
	}
	return defaultValue
}

// publishFinding publishes a security finding to Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	// Inject trace context for span linking across service boundaries
	finding.TraceContext = telemetry.InjectTraceContext(ctx)
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}
