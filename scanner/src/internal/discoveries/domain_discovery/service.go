package domain_discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/subfinderx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	dnsRetryAttempts = 3
	dnsRetryDelay    = 200 * time.Millisecond
)

type Service struct {
	redis           *redis.Client
	logger          *zap.Logger
	subfinderClient *subfinderx.Client
	tracer          trace.Tracer
}

func NewService(redisClient *redis.Client, logger *zap.Logger) (*Service, error) {
	subfinderClient, err := subfinderx.NewClient(logger)
	if err != nil {
		return nil, err
	}
	return &Service{
		redis:           redisClient,
		logger:          logger,
		subfinderClient: subfinderClient,
		tracer:          otel.Tracer("domain-discovery"),
	}, nil
}

// ProcessJob processes a discovery job using subfinder
func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
	ctx, span := s.tracer.Start(ctx, "discover_domain",
		trace.WithAttributes(
			attribute.String("org.id", job.OrgID),
			attribute.String("trace.id", job.TraceID),
			attribute.String("host", job.Host),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery job with subfinder",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("host", job.Host),
	)

	now := time.Now()

	// Resolve IP for domain (if applicable)
	var resolvedIP *string
	if s.isDomain(job.Host) {
		if ip, err := s.resolveIP(ctx, job.Host); err == nil {
			// Reject domains that resolve to private/reserved IPs to prevent
			// SSRF attacks against internal infrastructure via DNS.
			if isPrivate, checkErr := shared.IsPrivateIP(ip); checkErr == nil && isPrivate {
				s.logger.Warn("Blocking domain job: resolves to private IP",
					zap.String("trace_id", job.TraceID),
					zap.String("org_id", job.OrgID),
					zap.String("host", job.Host),
					zap.String("resolved_ip", ip),
				)
				return nil
			}
			resolvedIP = &ip
			s.logger.Info("Resolved domain to IP",
				zap.String("domain", job.Host),
				zap.String("ip", ip),
			)
		}
	}

	// Determine asset type and generate deterministic ID (org-scoped)
	assetType := determineDomainAssetType(job.Host, job.ParentID)
	var discoveryID string
	if assetType == shared.AssetTypeDomain {
		discoveryID = shared.GenerateDomainID(job.OrgID, job.Host)
	} else {
		discoveryID = shared.GenerateSubdomainID(job.OrgID, job.Host)
	}

	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	// Publish root asset finding
	if err := s.publishFinding(ctx, shared.DiscoveryFinding{
		DiscoveryID: discoveryID,
		AssetType:   assetType,
		TraceID:     job.TraceID,
		ScanID:      job.ScanID,  // Pass through scan_id
		OrgID:       job.OrgID,
		Source:      "subfinder",
		ParentID:    job.ParentID,
		Host:        job.Host,
		IP:          resolvedIP,
		Port:        job.Port,
		Protocol:    job.Protocol,
		Status:      shared.AssetStatusActive,
		Metadata:    job.Metadata,
		Timestamp:   now,
	}); err != nil {
		return err
	}

	// Run subdomain discovery inline — keeps the message unACKed until enumeration finishes,
	// ensuring at-least-once delivery and safe serial use of the shared subfinder runner.
	if job.ParentID == nil && job.Port == nil && s.isDomain(job.Host) {
		if err := s.discoverSubdomains(ctx, job.TraceID, job.ScanID, job.OrgID, job.Host); err != nil {
			s.logger.Error("subfinder subdomain discovery failed",
				zap.String("host", job.Host),
				zap.Error(err),
			)
		}
	}

	return nil
}

// discoverSubdomains uses subfinder to discover and publish subdomain findings
func (s *Service) discoverSubdomains(ctx context.Context, traceID string, scanID *string, orgID, domain string) error {
	ctx, span := s.tracer.Start(ctx, "subfinder_subdomain_discovery",
		trace.WithAttributes(
			attribute.String("org.id", orgID),
			attribute.String("trace.id", traceID),
			attribute.String("domain", domain),
		),
	)
	defer span.End()

	s.logger.Info("Starting subfinder subdomain discovery",
		zap.String("trace_id", traceID),
		zap.String("org_id", orgID),
		zap.String("domain", domain),
	)

	// Discover subdomains using subfinder
	subdomains, err := s.subfinderClient.DiscoverSubdomains(ctx, domain)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("scan.success", false))
		return err
	}

	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	span.SetAttributes(attribute.Int("subdomain.count", len(subdomains)))

	if len(subdomains) == 0 {
		s.logger.Info("No subdomains discovered", zap.String("domain", domain))
		return nil
	}

	now := time.Now()
	// Generate parent domain ID (org-scoped)
	parentDomainID := shared.GenerateDomainID(orgID, domain)

	// Publish each discovered subdomain
	for _, subdomainName := range subdomains {
		// Skip empty strings and wildcards
		if subdomainName == "" || subdomainName == "*" {
			continue
		}

		// Build the full subdomain
		fullSubdomain := subdomainName
		if !contains(subdomainName, domain) {
			fullSubdomain = subdomainName + "." + domain
		}

		// Resolve IP for subdomain, filtering private IPs to prevent SSRF
		var resolvedIP *string
		if ip, err := s.resolveIP(ctx, fullSubdomain); err == nil {
			if isPrivate, checkErr := shared.IsPrivateIP(ip); checkErr == nil && isPrivate {
				s.logger.Warn("Skipping subdomain: resolves to private IP",
					zap.String("trace_id", traceID),
					zap.String("org_id", orgID),
					zap.String("subdomain", fullSubdomain),
					zap.String("resolved_ip", ip),
				)
				continue
			}
			resolvedIP = &ip
			s.logger.Debug("Resolved subdomain to IP",
				zap.String("subdomain", fullSubdomain),
				zap.String("ip", ip),
			)
		}

		// Generate deterministic ID for subdomain (org-scoped)
		subdomainID := shared.GenerateSubdomainID(orgID, fullSubdomain)

		// Publish subdomain finding
		if err := s.publishFinding(ctx, shared.DiscoveryFinding{
			DiscoveryID: subdomainID,
			AssetType:   shared.AssetTypeSubdomain,
			TraceID:     traceID,
			ScanID:      scanID,  // Pass through scan_id
			OrgID:       orgID,
			Source:      "subfinder",
			ParentID:    &parentDomainID,
			Host:        fullSubdomain,
			IP:          resolvedIP,
			Port:        nil,
			Protocol:    nil,
			Status:      shared.AssetStatusActive,
			Metadata:    nil, // Keep field for future extensibility
			Timestamp:   now,
		}); err != nil {
			s.logger.Error("Failed to publish subdomain finding",
				zap.String("subdomain", fullSubdomain),
				zap.Error(err),
			)
			continue
		}

		s.logger.Info("Published subdomain finding",
			zap.String("subdomain", fullSubdomain),
		)
	}

	return nil
}

// publishFinding publishes a discovery finding to the domain discovery results stream
func (s *Service) publishFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
	// Inject trace context for span linking across service boundaries
	finding.TraceContext = telemetry.InjectTraceContext(ctx)

	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryResults, finding, 0); err != nil {
		s.logger.Error("Failed to publish finding to stream",
			zap.String("stream", shared.StreamDomainDiscoveryResults),
			zap.Error(err),
		)
		return err
	}

	s.logger.Debug("Published finding to stream",
		zap.String("stream", shared.StreamDomainDiscoveryResults),
		zap.String("host", finding.Host),
		zap.String("source", finding.Source),
	)

	return nil
}

// isDomain checks if the host is a domain (simple heuristic)
func (s *Service) isDomain(host string) bool {
	// Simple heuristic: if it contains only numbers and dots, it's an IP
	for _, c := range host {
		if !(c >= '0' && c <= '9' || c == '.') {
			return true
		}
	}
	return false
}

// contains checks if a string contains a substring (for subdomain building)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[len(s)-len(substr)-1:] == "."+substr || s[:len(substr)+1] == substr+"."))
}

// resolveIP resolves a domain name to its IPv4 address using DNS.
// Retries up to dnsRetryAttempts times with dnsRetryDelay between attempts
// to handle transient DNS failures.
func (s *Service) resolveIP(ctx context.Context, domain string) (string, error) {
	resolver := &net.Resolver{}
	var lastErr error

	for attempt := 1; attempt <= dnsRetryAttempts; attempt++ {
		ips, err := resolver.LookupIP(ctx, "ip4", domain)
		if err == nil && len(ips) > 0 {
			if attempt > 1 {
				s.logger.Info("DNS resolution succeeded after retry",
					zap.String("domain", domain),
					zap.Int("attempt", attempt),
				)
			}
			return ips[0].String(), nil
		}

		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("no IP addresses found for domain: %s", domain)
		}

		s.logger.Debug("DNS resolution attempt failed",
			zap.String("domain", domain),
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", dnsRetryAttempts),
			zap.Error(lastErr),
		)

		if attempt < dnsRetryAttempts {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(dnsRetryDelay):
			}
		}
	}

	return "", lastErr
}
