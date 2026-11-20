package email_security_scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	var checkErr error
	if target.AssetType == shared.AssetTypeSubdomain {
		allResults, checkErr = s.scanSubdomain(dnsCtx, span, target)
	} else {
		allResults, checkErr = s.scanRootDomain(dnsCtx, span, target)
	}
	if ctx.Err() != nil {
		return ctx.Err() // shutdown: leave the trigger pending
	}

	span.SetAttributes(attribute.Int("findings.count", len(allResults)))
	span.SetAttributes(attribute.Bool("scan.success", checkErr == nil))
	span.SetStatus(codes.Ok, "")

	// Publish the findings, then the coverage that lists them. A failed publish is returned
	// before the coverage, so the consumer retries the target.
	reported, err := s.publishUniqueFindings(ctx, allResults, target)
	if err != nil {
		return err
	}
	if checkErr != nil {
		s.logger.Info("Email security check incomplete; its findings on this target stay open",
			zap.String("target", target.Target), zap.Error(checkErr))
		return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, nil, checkErr))
	}
	return s.publishFinding(ctx, shared.TargetCoverage(findingSource, target, reported, nil))
}

// scanRootDomain runs the full email security check suite on a root domain (eTLD+1):
// SPF, DMARC, DKIM, and zone transfer (AXFR). It returns what it found and the errors of the
// checks that could not complete.
func (s *Service) scanRootDomain(ctx context.Context, span trace.Span, target ScanTarget) ([]EmailCheckResult, error) {
	span.SetAttributes(attribute.String("email.scan_scope", "full"))

	spf, spfErr := checkSPF(ctx, s.resolver, target.Target)
	dmarc, dmarcErr := checkDMARC(ctx, s.resolver, target.Target)
	axfr, axfrErr := checkZoneTransfer(ctx, s.resolver, target.Target)
	results := append(append(spf, dmarc...), checkDKIM(ctx, s.resolver, target.Target)...)
	return append(results, axfr...), errors.Join(spfErr, dmarcErr, axfrErr)
}

// scanSubdomain performs an MX lookup to determine if the subdomain handles email.
// If MX records exist, it runs SPF and DKIM checks only (DMARC inherits from parent,
// AXFR is zone-level). If no MX records exist, the subdomain is skipped entirely: the
// check is complete with no findings. A failed MX lookup makes the check incomplete.
func (s *Service) scanSubdomain(ctx context.Context, span trace.Span, target ScanTarget) ([]EmailCheckResult, error) {
	mxRecords, err := s.resolver.LookupMX(ctx, target.Target)
	if err != nil && !isDNSNotFound(err) {
		span.SetAttributes(attribute.String("email.scan_scope", "skipped_mx_error"))
		return nil, fmt.Errorf("MX lookup: %w", err)
	}
	if len(mxRecords) == 0 {
		span.SetAttributes(attribute.String("email.scan_scope", "skipped_no_mx"))
		s.logger.Debug("Skipping subdomain with no MX records",
			zap.String("target", target.Target),
			zap.String("org_id", target.OrgID),
		)
		return nil, nil
	}

	span.SetAttributes(attribute.String("email.scan_scope", "mx_only"))
	s.logger.Info("Subdomain has MX records, scanning SPF and DKIM",
		zap.String("target", target.Target),
		zap.Int("mx_count", len(mxRecords)),
		zap.String("org_id", target.OrgID),
	)

	spf, spfErr := checkSPF(ctx, s.resolver, target.Target)
	return append(spf, checkDKIM(ctx, s.resolver, target.Target)...), spfErr
}

// publishUniqueFindings publishes deduplicated findings to Redis and returns their keys. It
// stops at the first failed publish.
func (s *Service) publishUniqueFindings(ctx context.Context, results []EmailCheckResult, target ScanTarget) ([]shared.FindingKey, error) {
	seen := make(map[string]bool)
	var reported []shared.FindingKey

	for _, check := range results {
		if seen[check.FindingType] {
			continue
		}
		seen[check.FindingType] = true

		finding := convertToSecurityFinding(check, target)
		if err := s.publishFinding(ctx, finding); err != nil {
			return nil, fmt.Errorf("publish email finding %s: %w", check.FindingType, err)
		}
		reported = append(reported, shared.FindingKey{FindingType: finding.FindingType, Title: finding.Title})

		s.logger.Info("Published email security finding",
			zap.String("finding_type", check.FindingType),
			zap.String("severity", check.Severity),
			zap.String("org_id", target.OrgID),
		)
	}
	return reported, nil
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
