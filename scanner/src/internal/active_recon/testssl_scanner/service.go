package testssl_scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if err != nil && ctx.Err() != nil {
		// Shutdown cut the run off. This is expected: the message stays unACKed and the
		// next start closes the scan as interrupted.
		s.logger.Info("testssl.sh scan stopped by shutdown",
			zap.String("target", target.Target),
		)
		span.SetAttributes(attribute.Bool("scan.success", false))
		return err
	}
	if err == nil {
		// Like nuclei, only a target that still answers after the run makes it evidence.
		if rerr := shared.Reachable(ctx, target.Target); rerr != nil {
			err = fmt.Errorf("target not reachable after the run: %w", rerr)
		}
	}
	if err != nil {
		// A failed run is a result, not a handler error: coverage "error" keeps every
		// testssl finding on this target open. The findings the run did write are still
		// real and are published below.
		s.logger.Error("testssl.sh scan failed",
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
		s.logger.Info("testssl.sh scan completed",
			zap.String("target", target.Target),
			zap.Int("findings_count", len(findings)),
		)
	}
	span.SetAttributes(attribute.Int("findings.count", len(findings)))

	// Publish each finding, then the coverage. A failed publish is returned before the
	// coverage, so the consumer retries the target. Coverage "ok" lists the findings only
	// for a complete run.
	var reported []shared.FindingKey
	for _, testSSLFinding := range findings {
		finding := s.convertToSecurityFinding(testSSLFinding, target)
		// Skip findings downgraded to info by severity overrides (e.g. LUCKY13, SWEET32, CRIME_TLS)
		if strings.EqualFold(finding.Severity, shared.SeverityInfo) {
			continue
		}
		if err := s.publishFinding(ctx, finding); err != nil {
			return fmt.Errorf("publish testssl finding %s: %w", testSSLFinding.ID, err)
		}
		reported = append(reported, shared.FindingKey{FindingType: finding.FindingType, Title: finding.Title})
	}
	if err != nil {
		return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, nil, err))
	}
	return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, reported, nil))
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
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, fmt.Errorf("testssl.sh command failed: %w (output: %s)", err, tail(output))
		}
		exitCode = exitErr.ExitCode()
	}

	// testssl.sh writes the JSON file also when it stops early; only a run that provably
	// checked everything is evidence (runComplete). The findings it wrote before it stopped
	// are returned also then.
	jsonData, readErr := os.ReadFile(tmpPath)
	if readErr != nil && exitCode == 0 {
		return nil, fmt.Errorf("failed to read JSON output: %w", readErr)
	}
	findings, parseErr := s.parseTestSSLOutput(jsonData)
	if err := runComplete(exitCode, jsonData); err != nil {
		s.logger.Debug("testssl.sh run incomplete",
			zap.String("target", target),
			zap.Int("exit_code", exitCode),
			zap.String("output", tail(output)),
		)
		return findings, err
	}
	return findings, parseErr
}

// tail returns at most the last 500 bytes of b, for error messages.
func tail(b []byte) string {
	if len(b) > 500 {
		b = b[len(b)-500:]
	}
	return string(b)
}

// parseTestSSLOutput returns the security issues (LOW and up) in the vulnerabilities and
// headerResponse lists of testssl.sh's JSON output. It also returns the issues it read
// before an error, so a file cut off mid-run still gives the findings written before the cut.
func (s *Service) parseTestSSLOutput(output []byte) ([]TestSSLFinding, error) {
	if len(bytes.TrimSpace(output)) == 0 {
		return nil, nil
	}
	allFindings, err := readFindingLists(output)
	if err != nil {
		s.logger.Warn("Failed to parse testssl.sh JSON output",
			zap.Error(err),
			zap.Int("findings_read", len(allFindings)),
			zap.String("output_preview", string(output[:min(len(output), 500)])),
		)
		err = fmt.Errorf("failed to parse testssl.sh JSON: %w", err)
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

	return filteredFindings, err
}

// readFindingLists reads the findings of the vulnerabilities and headerResponse lists of every
// scanResult entry. testssl.sh output is { ..., "scanResult": [ { "vulnerabilities": [...],
// "headerResponse": [...], ... } ], "scanTime": ... }. It reads the JSON as a stream and
// returns the findings it read before the first error.
func readFindingLists(data []byte) ([]TestSSLFinding, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var found []TestSSLFinding
	// eachKey calls fn for every key of the object that starts at the next token. fn must
	// consume the value.
	eachKey := func(fn func(key string) error) error {
		if err := expectDelim(dec, '{'); err != nil {
			return err
		}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if err := fn(tok.(string)); err != nil {
				return err
			}
		}
		return expectDelim(dec, '}')
	}
	// eachElem calls fn for every element of the array that starts at the next token.
	eachElem := func(fn func() error) error {
		if err := expectDelim(dec, '['); err != nil {
			return err
		}
		for dec.More() {
			if err := fn(); err != nil {
				return err
			}
		}
		return expectDelim(dec, ']')
	}
	skip := func() error {
		var v json.RawMessage
		return dec.Decode(&v)
	}

	err := eachKey(func(key string) error {
		if key != "scanResult" {
			return skip()
		}
		return eachElem(func() error {
			return eachKey(func(key string) error {
				if key != "vulnerabilities" && key != "headerResponse" {
					return skip()
				}
				return eachElem(func() error {
					var f TestSSLFinding
					if err := dec.Decode(&f); err != nil {
						return err
					}
					found = append(found, f)
					return nil
				})
			})
		})
	})
	return found, err
}

// expectDelim reads the next token and returns an error unless it is the delimiter d. At the
// end of a cut-off input the error is io.ErrUnexpectedEOF.
func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	if err != nil {
		return err
	}
	if tok != d {
		return fmt.Errorf("unexpected %v in testssl.sh JSON, want %v", tok, d)
	}
	return nil
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
		Source:      findingSource,
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
	finding.TraceContext = telemetry.InjectTraceContext(ctx)
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}
