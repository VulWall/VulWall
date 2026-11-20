package nuclei_scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/VulWall/VulWall/scanner/src/internal/core/execx"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service handles Nuclei vulnerability scanning
type Service struct {
	redis      *redis.Client
	logger     *zap.Logger
	tracer     trace.Tracer
	cron       *cron.Cron
	rootClient *http.Client // GETs the target root after a run (rootBlocked)
}

// NewService creates a new Nuclei scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	if _, ok := rateLimit(); !ok {
		logger.Warn("NUCLEI_RATE_LIMIT must be a positive integer; using the default",
			zap.String("value", config.GetEnv(config.EnvNucleiRateLimit, "")),
			zap.Int("default", DefaultRateLimit),
		)
	}
	if _, err := interactshArgs(); err != nil {
		logger.Warn("Out-of-band (interactsh) checks stay off", zap.Error(err))
	}
	return &Service{
		redis:      redisClient,
		logger:     logger,
		tracer:     otel.Tracer("nuclei-scanner"),
		rootClient: newRootClient(),
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

	// The first update runs in Consumer.Start before it reads any message.

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

// updateTemplates runs nuclei -update-templates and logs the result
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

	cmd := execx.Command(updateCtx, "nuclei", "-update-templates", "-update-template-dir", templatesDir())
	output, err := cmd.CombinedOutput()

	// Get version after update
	versionAfter := s.getTemplateVersion(ctx)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		s.logger.Error("Nuclei template update failed",
			zap.String("version_before", versionBefore),
			zap.String("version_after", versionAfter),
			zap.String("output", string(output)),
			zap.Error(err),
		)
		return
	}
	span.SetStatus(codes.Ok, "")
	s.logger.Info("Nuclei templates updated",
		zap.String("version_before", versionBefore),
		zap.String("version_after", versionAfter),
	)
}

// getTemplateVersion returns current Nuclei template version
func (s *Service) getTemplateVersion(ctx context.Context) string {
	// Bound this probe so a hung `nuclei -tv` can't push the lock-held time past
	// TemplateUpdateLockTTL (keeps the TTL-vs-update-timeout invariant true).
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := execx.Command(ctx, "nuclei", "-tv")
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

	// Every address of the target must be public before nuclei runs: a name with a private
	// answer is not scanned (coverage error). -lna repeats the check at dial time, which also
	// covers a DNS answer that changes between this lookup and nuclei's own.
	if err := publicTarget(ctx, target.Target); err != nil {
		if ctx.Err() != nil {
			s.logger.Info("Nuclei scan stopped by shutdown", zap.String("target", target.Target))
			return ctx.Err()
		}
		s.logger.Warn("Nuclei target not scanned",
			zap.String("target", target.Target),
			zap.Error(err),
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("scan.success", false))
		return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, nil, err))
	}

	// Run Nuclei scan
	findings, err := s.runNucleiScan(ctx, target.Target, "low,medium,high,critical")
	if err != nil && ctx.Err() != nil {
		// Shutdown cut the run off. This is expected: the message stays unACKed and the
		// next start closes the scan as interrupted.
		s.logger.Info("Nuclei scan stopped by shutdown",
			zap.String("target", target.Target),
		)
		span.SetAttributes(attribute.Bool("scan.success", false))
		return err
	}
	if err == nil {
		// nuclei reports "no findings" also when the target stopped answering during the run
		// (down, or a WAF that banned the scanner). Only a target that still accepts a
		// connection afterwards makes the run evidence.
		if rerr := shared.Reachable(ctx, reachAddrs(target.Target)...); rerr != nil {
			err = fmt.Errorf("target not reachable after the run: %w", rerr)
		} else if berr := rootBlocked(ctx, s.rootClient, target.Target); berr != nil {
			// nuclei says nothing about a 403 or a WAF challenge on every request: its
			// templates then met the block, not the application.
			err = fmt.Errorf("target blocks the scanner: %w", berr)
		}
	}
	if err != nil {
		// A failed run is a result, not a handler error: it is recorded as coverage
		// "error", so the scan resolves no nuclei finding on this target. The matches the
		// run did report are still real and are published below.
		s.logger.Error("Nuclei scan failed",
			zap.String("target", target.Target),
			zap.Int("findings_count", len(findings)),
			zap.Error(err),
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("scan.success", false))
	} else {
		span.SetAttributes(attribute.Bool("scan.success", true))
		span.SetStatus(codes.Ok, "")
		s.logger.Info("Nuclei scan completed",
			zap.String("target", target.Target),
			zap.Int("findings_count", len(findings)),
		)
	}
	span.SetAttributes(attribute.Int("findings.count", len(findings)))

	// Publish each finding, then the coverage. A failed publish is returned before the
	// coverage, so the consumer retries the target and the scan never holds an "ok" for
	// findings it did not receive. Coverage "ok" lists the findings only for a complete run.
	reported := make([]shared.FindingKey, 0, len(findings))
	for _, nucleiOutput := range findings {
		finding := s.convertToSecurityFinding(nucleiOutput, target)
		if err := s.publishFinding(ctx, finding); err != nil {
			return fmt.Errorf("publish nuclei finding %s: %w", nucleiOutput.TemplateID, err)
		}
		reported = append(reported, shared.FindingKey{FindingType: finding.FindingType, Title: finding.Title})
	}
	if err != nil {
		return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, nil, err))
	}
	return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, reported, nil))
}

// publicTarget resolves the host of target (a bare host or IP, or a URL) and returns an error
// unless every address is public (shared.ResolvePublicIPs; ALLOW_PRIVATE_TARGETS lifts the
// range check). A failed lookup is an error too: there is nothing to scan.
func publicTarget(ctx context.Context, target string) error {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	_, err := shared.ResolvePublicIPs(ctx, host)
	return err
}

// reachAddrs returns the host:port addresses that show a nuclei target is still up: the URL's
// own port, or 443 and 80 for a bare host or IP.
func reachAddrs(target string) []string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		port := u.Port()
		if port == "" {
			port = map[string]string{"https": "443"}[u.Scheme]
			if port == "" {
				port = "80"
			}
		}
		return []string{net.JoinHostPort(u.Hostname(), port)}
	}
	return []string{net.JoinHostPort(target, "443"), net.JoinHostPort(target, "80")}
}

// nucleiArgs builds the nuclei command line for one target.
func nucleiArgs(target, severity string) []string {
	args := []string{
		"-u", target,
		"-t", templatesDir(),
		"-j",
		// Not -silent: it hides the stderr log that tells a finished run from one that
		// skipped the target (runProblem). -nc keeps that log free of colour codes; -duc
		// stops nuclei from updating itself or the templates during a scan (the template
		// updater does that, under a lock).
		"-nc",
		"-duc",
		"-severity", severity,
	}
	rl, _ := rateLimit()
	args = append(args, "-rl", strconv.Itoa(rl))
	ia, _ := interactshArgs()
	args = append(args, ia...)

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

// rateLimit returns the nuclei request rate (-rl) from NUCLEI_RATE_LIMIT, or DefaultRateLimit
// when it is unset. ok is false when the variable is set but not a positive integer; the
// default is used then too.
func rateLimit() (rl int, ok bool) {
	v := strings.TrimSpace(config.GetEnv(config.EnvNucleiRateLimit, ""))
	if v == "" {
		return DefaultRateLimit, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return DefaultRateLimit, false
	}
	return n, true
}

// interactshArgs returns nuclei's interactsh (OAST) arguments. Off by default (-ni): with it
// on, a vulnerable target calls back to an interactsh server, by default ProjectDiscovery's
// public ones (oast.*), which so learn of the target. NUCLEI_INTERACTSH=on|true turns it on;
// NUCLEI_INTERACTSH_SERVER (an https URL) and NUCLEI_INTERACTSH_TOKEN select a self-hosted
// server. An invalid server keeps it off (err says why) rather than fall back to the public
// servers. The error contains neither the token nor the server value.
func interactshArgs() ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(config.GetEnv(config.EnvNucleiInteractsh, ""))) {
	case "on", "true":
	default:
		return []string{"-ni"}, nil
	}
	var args []string
	if server := strings.TrimSpace(config.GetEnv(config.EnvNucleiInteractshServer, "")); server != "" {
		u, err := url.Parse(server)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			// The value is not echoed: it may carry credentials.
			return []string{"-ni"}, fmt.Errorf("%s must be an https URL without credentials", config.EnvNucleiInteractshServer)
		}
		args = append(args, "-iserver", server)
	}
	if token := strings.TrimSpace(config.GetEnv(config.EnvNucleiInteractshToken, "")); token != "" {
		args = append(args, "-itoken", token)
	}
	return args, nil
}

// templatesDir is where nuclei templates are installed and read from.
// NUCLEI_TEMPLATES_DIR overrides the default, $HOME/nuclei-templates (the
// nuclei default), so the container can keep templates in a volume.
func templatesDir() string {
	if dir := config.GetEnv(config.EnvNucleiTemplatesDir, ""); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "nuclei-templates"
	}
	return filepath.Join(home, "nuclei-templates")
}

// runNucleiScan executes Nuclei scanner on the target. stdout carries the JSONL results,
// stderr the log; a run is only evidence when runProblem finds nothing wrong in the log.
// The results that parse are returned also with an error: a match from a run that did not
// finish is still a match.
func (s *Service) runNucleiScan(ctx context.Context, target, severity string) ([]NucleiOutput, error) {
	cmd := execx.Command(ctx, "nuclei", nucleiArgs(target, severity)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	findings, parseErr := parseNucleiOutput(stdout.Bytes())
	if err != nil {
		// nuclei exits 0 also when it found nothing; any other exit is a failed run
		// (for example exit 1 with "[FTL] Could not run nuclei: no templates provided").
		return findings, fmt.Errorf("nuclei command failed: %w (stderr: %s)", err, logTail(stderr.Bytes()))
	}
	if err := runProblem(target, stderr.Bytes()); err != nil {
		s.logger.Debug("Nuclei run incomplete",
			zap.String("target", target),
			zap.String("stderr", logTail(stderr.Bytes())),
		)
		return findings, err
	}
	s.logger.Info("Nuclei run finished",
		zap.String("target", target),
		zap.String("summary", scanSummary(stderr.Bytes())),
	)
	return findings, parseErr
}

// parseNucleiOutput parses nuclei's JSONL results. It returns every line that parses; a line
// that does not may be a lost finding, so it also returns an error that fails the run.
func parseNucleiOutput(out []byte) ([]NucleiOutput, error) {
	var findings []NucleiOutput
	var firstErr error
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var nucleiOutput NucleiOutput
		if err := json.Unmarshal([]byte(line), &nucleiOutput); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("unreadable nuclei result line: %w", err)
			}
			continue
		}
		findings = append(findings, nucleiOutput)
	}
	return findings, firstErr
}

// runProblem returns why a nuclei run that exited 0 is no evidence, or nil. Observed with
// nuclei v3.11.1 (-j -nc -duc, log on stderr):
//   - a finished run logs "[INF] Scan completed in <duration>. <N matches found|No results found>."
//   - a target that stopped answering during the run, or never answered, is dropped with
//     "[INF] Skipped <host:port> from target list as found unresponsive 30 times" or
//     "... as found unresponsive permanently: cause=..." and the run still exits 0;
//   - "[FTL] ..." is fatal.
//
// Skip lines for other ports (templates probe for example :4040) do not count: only the
// target's own addresses (reachAddrs). "[ERR]" and "[WRN]" lines are not checked: nuclei logs
// harmless ones on every run (a missing .nuclei-ignore file, templates with runtime errors).
func runProblem(target string, stderr []byte) error {
	completed := false
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "[FTL]") {
			return fmt.Errorf("nuclei failed: %s", strings.TrimSpace(line))
		}
		for _, addr := range reachAddrs(target) {
			if strings.Contains(line, "Skipped "+addr+" from target list") {
				return fmt.Errorf("nuclei dropped the target during the run: %s", strings.TrimSpace(line))
			}
		}
		if strings.Contains(line, "Scan completed in") {
			completed = true
		}
	}
	if !completed {
		return errors.New("nuclei did not report a completed scan")
	}
	return nil
}

// scanSummary returns nuclei's "Scan completed in ..." log line, for the log.
func scanSummary(stderr []byte) string {
	summary := ""
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.Contains(line, "Scan completed in") {
			summary = strings.TrimSpace(line)
		}
	}
	return summary
}

// logTail returns at most the last 1000 bytes of b, for error messages.
func logTail(b []byte) string {
	if len(b) > 1000 {
		b = b[len(b)-1000:]
	}
	return strings.TrimSpace(string(b))
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
		ScanID:      target.ScanID, // Pass through scan_id
		OrgID:       target.OrgID,
		Source:      findingSource,
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
