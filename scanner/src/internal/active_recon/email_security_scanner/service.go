package email_security_scanner

import (
	"context"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service represents the email security scanner service
type Service struct {
	redis    *redis.Client
	logger   *zap.Logger
	tracer   trace.Tracer
	resolver *net.Resolver
}

// NewService creates a new email security scanner service
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:    redisClient,
		logger:   logger,
		tracer:   otel.Tracer("email-security-scanner"),
		resolver: net.DefaultResolver,
	}
}

// ProcessDiscovery processes a discovery target and checks email security (SPF, DKIM, DMARC)
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "emailscanner",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery for EmailSecurityScanner",
		zap.String("target", target.Target),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Use a timeout for DNS lookups
	dnsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Run all email security checks
	var allResults []EmailCheckResult
	allResults = append(allResults, checkSPF(dnsCtx, s.resolver, target.Target)...)
	allResults = append(allResults, checkDMARC(dnsCtx, s.resolver, target.Target)...)
	allResults = append(allResults, checkDKIM(dnsCtx, s.resolver, target.Target)...)

	span.SetAttributes(attribute.Int("findings.count", len(allResults)))

	// Publish deduplicated findings
	s.publishUniqueFindings(ctx, allResults, target)

	return nil
}

// publishUniqueFindings publishes deduplicated findings to Redis
func (s *Service) publishUniqueFindings(ctx context.Context, results []EmailCheckResult, target ScanTarget) {
	seen := make(map[string]bool)

	for _, check := range results {
		if seen[check.FindingType] {
			continue
		}
		seen[check.FindingType] = true

		finding := convertToSecurityFinding(check, target)
		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish finding",
				zap.String("finding_type", check.FindingType),
				zap.String("domain", target.Target),
				zap.Error(err),
			)
			continue
		}

		s.logger.Info("Published email security finding",
			zap.String("finding_type", check.FindingType),
			zap.String("severity", check.Severity),
			zap.String("org_id", target.OrgID),
		)
	}
}

// publishFinding publishes a security finding to the Redis stream
func (s *Service) publishFinding(ctx context.Context, finding shared.SecurityFinding) error {
	finding.TraceContext = telemetry.InjectTraceContext(ctx)
	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, finding, 0)
}

// convertToSecurityFinding converts an email check result to SecurityFinding format
func convertToSecurityFinding(check EmailCheckResult, target ScanTarget) shared.SecurityFinding {
	metadata := map[string]interface{}{
		"domain":     target.Target,
		"references": check.References,
	}

	if check.Value != "" {
		metadata["record_value"] = check.Value
	}

	return shared.SecurityFinding{
		TraceID:     target.TraceID,
		ScanID:      target.ScanID,
		OrgID:       target.OrgID,
		Source:      "email-security",
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
