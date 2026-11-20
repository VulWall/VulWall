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

	// Count total findings
	totalFindings := 0
	for _, result := range allResults {
		totalFindings += len(result.checks)
	}
	span.SetAttributes(attribute.Int("findings.count", totalFindings))
	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	// Publish unique findings to Redis
	s.publishUniqueFindings(ctx, allResults, target)

	return nil
}

// scanBothProtocols scans both HTTP and HTTPS protocols concurrently
func (s *Service) scanBothProtocols(ctx context.Context, target ScanTarget) []protocolScanResult {
	protocols := []string{"http", "https"}
	results := make(chan protocolScanResult, len(protocols))

	var wg sync.WaitGroup

	for _, protocol := range protocols {
		wg.Add(1)
		go func(proto string) {
			defer wg.Done()

			url := fmt.Sprintf("%s://%s", proto, target.Target)
			checks, err := s.scanner.Scan(ctx, url)

			if err != nil {
				s.logger.Debug("Failed to scan URL",
					zap.String("url", url),
					zap.Error(err),
				)
			}

			results <- protocolScanResult{
				protocol: proto,
				url:      url,
				checks:   checks,
			}
		}(protocol)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []protocolScanResult
	for result := range results {
		if len(result.checks) > 0 {
			allResults = append(allResults, result)
		}
	}

	return allResults
}

// publishUniqueFindings publishes deduplicated header findings to Redis
func (s *Service) publishUniqueFindings(ctx context.Context, results []protocolScanResult, target ScanTarget) {
	// Dedup by finding_type across protocols (same header issue on HTTP and HTTPS = one finding)
	seen := make(map[string]bool)

	for _, result := range results {
		for _, check := range result.checks {
			key := check.FindingType
			if seen[key] {
				continue
			}
			seen[key] = true

			finding := convertToSecurityFinding(check, result.url, target)
			if err := s.publishFinding(ctx, finding); err != nil {
				s.logger.Error("Failed to publish finding",
					zap.String("header", check.HeaderName),
					zap.String("finding_type", check.FindingType),
					zap.Error(err),
				)
				continue
			}

			s.logger.Info("Published header finding",
				zap.String("header", check.HeaderName),
				zap.String("finding_type", check.FindingType),
				zap.String("severity", check.Severity),
				zap.String("org_id", target.OrgID),
			)
		}
	}
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
		Source:      "http-headers",
		DiscoveryID: target.DiscoveryID,
		FindingType: check.FindingType,
		Severity:    check.Severity,
		Title:       check.Title,
		Description: check.Description,
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
}
