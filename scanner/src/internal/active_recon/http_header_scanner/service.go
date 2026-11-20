package http_header_scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/http_header_scanner/scanner"
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

// Service represents the HTTP header scanner service
type Service struct {
	redis   *redis.Client
	logger  *zap.Logger
	scanner scanner.Scanner
	tracer  trace.Tracer
}

// NewService creates a new HTTP header scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:   redisClient,
		logger:  logger,
		scanner: scanner.NewScanner(logger),
		tracer:  otel.Tracer("http-header-scanner"),
	}
}

// ProcessDiscovery processes a discovery target and checks HTTP security headers
// Scans both HTTP and HTTPS protocols in parallel
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "headerscanner",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery for HTTPHeaderScanner",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Scan both HTTP and HTTPS in parallel
	allResults := s.scanBothProtocols(ctx, target)
	if ctx.Err() != nil {
		return ctx.Err() // shutdown: leave the trigger pending
	}

	// The check is complete only when every protocol answered or refused the connection.
	var probeErrs []error
	totalFindings := 0
	for _, result := range allResults {
		probeErrs = append(probeErrs, result.err)
		totalFindings += len(result.checks)
	}
	span.SetAttributes(attribute.Int("findings.count", totalFindings))
	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	// Publish the findings, then the coverage that lists them. A failed publish is returned
	// before the coverage, so the consumer retries the target.
	reported, err := s.publishUniqueFindings(ctx, allResults, target)
	if err != nil {
		return err
	}
	if probeErr := shared.ProbeError(probeErrs...); probeErr != nil {
		s.logger.Info("Header check incomplete; its findings on this target stay open",
			zap.String("target", target.Target), zap.Error(probeErr))
		return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, nil, probeErr))
	}
	return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, reported, nil))
}

// scanBothProtocols scans both HTTP and HTTPS protocols concurrently and returns one result
// per protocol, with its error.
func (s *Service) scanBothProtocols(ctx context.Context, target ScanTarget) []protocolScanResult {
	protocols := []string{"http", "https"}
	results := make([]protocolScanResult, len(protocols))

	var wg sync.WaitGroup
	for i, proto := range protocols {
		wg.Add(1)
		go func() {
			defer wg.Done()
			url := fmt.Sprintf("%s://%s", proto, target.Target)
			checks, err := s.scanner.Scan(ctx, url)
			if err != nil {
				s.logger.Debug("Failed to scan URL", zap.String("url", url), zap.Error(err))
			}
			results[i] = protocolScanResult{protocol: proto, url: url, checks: checks, err: err}
		}()
	}
	wg.Wait()
	return results
}

// publishUniqueFindings publishes deduplicated header findings to Redis and returns their
// keys. It stops at the first failed publish.
func (s *Service) publishUniqueFindings(ctx context.Context, results []protocolScanResult, target ScanTarget) ([]shared.FindingKey, error) {
	// Dedup across protocols (same header issue on HTTP and HTTPS = one finding) by the key
	// ingestion stores findings under, (finding_type, title): a coarser key would drop a
	// finding that is still present and let the scan resolve it.
	seen := make(map[shared.FindingKey]bool)
	var reported []shared.FindingKey

	for _, result := range results {
		for _, check := range result.checks {
			finding := convertToSecurityFinding(check, result.url, target)
			key := shared.FindingKey{FindingType: finding.FindingType, Title: finding.Title}
			if seen[key] {
				continue
			}
			seen[key] = true

			if err := s.publishFinding(ctx, finding); err != nil {
				return nil, fmt.Errorf("publish header finding %s: %w", check.FindingType, err)
			}
			reported = append(reported, key)

			s.logger.Info("Published header finding",
				zap.String("header", check.HeaderName),
				zap.String("finding_type", check.FindingType),
				zap.String("severity", check.Severity),
				zap.String("org_id", target.OrgID),
			)
		}
	}
	return reported, nil
}

// publishFinding publishes a security finding to the Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	finding.TraceContext = telemetry.InjectTraceContext(ctx)
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}

// convertToSecurityFinding converts a header check result to SecurityFinding format
func convertToSecurityFinding(check scanner.HeaderCheckResult, pageURL string, target ScanTarget) shared.SecurityFinding {
	metadata := map[string]interface{}{
		"header_name": check.HeaderName,
		"present":     check.Present,
		"url":         pageURL,
		"references":  check.References,
	}

	if check.Value != "" {
		metadata["current_value"] = check.Value
	}

	if check.Present {
		metadata["issue_type"] = "weak-value"
	} else {
		metadata["issue_type"] = "missing"
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Source:      findingSource,
		DiscoveryID: target.DiscoveryID,
		FindingType: check.FindingType,
		Severity:    check.Severity,
		Title:       check.Title,
		Description: check.Description,
		References:  check.References,
		Metadata:    metadata,
		Status:      shared.FindingStatusOpen,
		Timestamp:   time.Now(),
	}
}

// protocolScanResult holds the result of scanning a single protocol
type protocolScanResult struct {
	protocol string
	url      string
	checks   []scanner.HeaderCheckResult
	err      error
}
