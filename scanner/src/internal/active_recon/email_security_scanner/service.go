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

// ProcessDiscovery processes a discovery target and checks email security (SPF, DKIM, DMARC).
//
// Root domains (eTLD+1) get the full check suite: SPF, DMARC, DKIM, and AXFR.
// Subdomains are MX-gated: only scanned if they have MX records (i.e., actually handle email).
// When a subdomain has MX records, only SPF and DKIM are checked because:
//   - DMARC inherits from the parent domain (RFC 7489 Section 6.6.3)
//   - AXFR is a zone-level check already covered by the root domain
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
	ctx, span := s.tracer.Start(ctx, "emailscanner",
		trace.WithAttributes(
			attribute.String("org.id", target.OrgID),
			attribute.String("trace.id", target.TraceID),
			attribute.String("discovery.id", target.DiscoveryID),
			attribute.String("target", target.Target),
			attribute.String("asset.type", target.AssetType),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery for EmailSecurityScanner",
		zap.String("target", target.Target),
		zap.String("asset_type", target.AssetType),
		zap.String("discovery_id", target.DiscoveryID),
		zap.String("org_id", target.OrgID),
	)

	// Use a timeout for DNS lookups
	dnsCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var allResults []EmailCheckResult

	if target.AssetType == shared.AssetTypeSubdomain {
		allResults = s.scanSubdomain(dnsCtx, span, target)
	} else {
		allResults = s.scanRootDomain(dnsCtx, span, target)
	}

	span.SetAttributes(attribute.Int("findings.count", len(allResults)))

	// Publish deduplicated findings
	s.publishUniqueFindings(ctx, allResults, target)

	return nil
}

// scanRootDomain runs the full email security check suite on a root domain (eTLD+1):
// SPF, DMARC, DKIM, and zone transfer (AXFR).
func (s *Service) scanRootDomain(ctx context.Context, span trace.Span, target ScanTarget) []EmailCheckResult {
	span.SetAttributes(attribute.String("email.scan_scope", "full"))

	var results []EmailCheckResult
	results = append(results, checkSPF(ctx, s.resolver, target.Target)...)
	results = append(results, checkDMARC(ctx, s.resolver, target.Target)...)
	results = append(results, checkDKIM(ctx, s.resolver, target.Target)...)
	results = append(results, checkZoneTransfer(ctx, s.resolver, target.Target)...)
	return results
}

// scanSubdomain performs an MX lookup to determine if the subdomain handles email.
// If MX records exist, it runs SPF and DKIM checks only (DMARC inherits from parent,
// AXFR is zone-level). If no MX records exist, the subdomain is skipped entirely.
func (s *Service) scanSubdomain(ctx context.Context, span trace.Span, target ScanTarget) []EmailCheckResult {
	mxRecords, err := s.resolver.LookupMX(ctx, target.Target)
	if err != nil {
		if isDNSNotFound(err) {
			span.SetAttributes(attribute.String("email.scan_scope", "skipped_no_mx"))
			s.logger.Debug("Skipping subdomain with no MX records",
				zap.String("target", target.Target),
				zap.String("org_id", target.OrgID),
			)
			return nil
		}
		// Transient error (timeout, SERVFAIL) — skip silently
		span.SetAttributes(attribute.String("email.scan_scope", "skipped_mx_error"))
		s.logger.Debug("MX lookup failed, skipping subdomain",
			zap.String("target", target.Target),
			zap.Error(err),
		)
		return nil
	}
	if len(mxRecords) == 0 {
		span.SetAttributes(attribute.String("email.scan_scope", "skipped_no_mx"))
		s.logger.Debug("Skipping subdomain with no MX records",
			zap.String("target", target.Target),
			zap.String("org_id", target.OrgID),
		)
		return nil
	}

	span.SetAttributes(attribute.String("email.scan_scope", "mx_only"))
	s.logger.Info("Subdomain has MX records, scanning SPF and DKIM",
		zap.String("target", target.Target),
		zap.Int("mx_count", len(mxRecords)),
		zap.String("org_id", target.OrgID),
	)

	var results []EmailCheckResult
	results = append(results, checkSPF(ctx, s.resolver, target.Target)...)
	results = append(results, checkDKIM(ctx, s.resolver, target.Target)...)
	return results
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
