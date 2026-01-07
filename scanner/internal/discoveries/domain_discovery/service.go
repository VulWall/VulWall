package domain_discovery

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/shodan"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	redis        *redis.Client
	logger       *zap.Logger
	shodanClient *shodan.Client
	tracer       trace.Tracer
}

func NewService(redisClient *redis.Client, shodanAPIKey string, logger *zap.Logger) *Service {
	return &Service{
		redis:        redisClient,
		logger:       logger,
		shodanClient: shodan.NewClient(shodanAPIKey, logger),
		tracer:       otel.Tracer("domain-discovery"),
	}
}

// ProcessJob processes a discovery job using Shodan
func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
	ctx, span := s.tracer.Start(ctx, "discover_domain",
		trace.WithAttributes(
			attribute.String("org.id", job.OrgID),
			attribute.String("trace.id", job.TraceID),
			attribute.String("host", job.Host),
		),
	)
	defer span.End()

	s.logger.Info("Processing discovery job with Shodan",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("host", job.Host),
	)

	now := time.Now()

	// Resolve IP for domain (if applicable)
	var resolvedIP *string
	if s.isDomain(job.Host) {
		if ip, err := s.resolveIP(ctx, job.Host); err == nil {
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

	// Publish root asset finding
	if err := s.publishFinding(ctx, shared.DiscoveryFinding{
		DiscoveryID: discoveryID,
		AssetType:   assetType,
		TraceID:     job.TraceID,
		ScanID:      job.ScanID,  // Pass through scan_id
		OrgID:       job.OrgID,
		Source:     "shodan",
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

	// Trigger Shodan subdomain discovery for root domains (no parent, no port)
	if job.ParentID == nil && job.Port == nil && s.isDomain(job.Host) {
		go func() {
			// Pass ctx to maintain trace context in goroutine
			if err := s.discoverSubdomains(ctx, job.TraceID, job.ScanID, job.OrgID, job.Host); err != nil {
				s.logger.Error("Shodan subdomain discovery failed",
					zap.String("host", job.Host),
					zap.Error(err),
				)
			}
		}()
	}

	return nil
}

// discoverSubdomains uses Shodan to discover and publish subdomain findings
func (s *Service) discoverSubdomains(ctx context.Context, traceID string, scanID *string, orgID, domain string) error {
	ctx, span := s.tracer.Start(ctx, "shodan_subdomain_discovery",
		trace.WithAttributes(
			attribute.String("org.id", orgID),
			attribute.String("trace.id", traceID),
			attribute.String("domain", domain),
		),
	)
	defer span.End()

	s.logger.Info("Starting Shodan subdomain discovery",
		zap.String("trace_id", traceID),
		zap.String("org_id", orgID),
		zap.String("domain", domain),
	)

	// Discover subdomains using Shodan
	subdomains, err := s.shodanClient.DiscoverSubdomains(ctx, domain)
	if err != nil {
		span.RecordError(err)
		return err
	}

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

		// Resolve IP for subdomain
		var resolvedIP *string
		if ip, err := s.resolveIP(ctx, fullSubdomain); err == nil {
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
			Source:     "shodan",
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

	// Use shared publisher utility with MAXLEN=10000 to prevent unbounded growth
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryResults, finding, 10000); err != nil {
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

// resolveIP resolves a domain name to its IP address using DNS
func (s *Service) resolveIP(ctx context.Context, domain string) (string, error) {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip4", domain)
	if err != nil {
		s.logger.Debug("Failed to resolve IP for domain",
			zap.String("domain", domain),
			zap.Error(err),
		)
		return "", err
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain: %s", domain)
	}

	return ips[0].String(), nil
}
