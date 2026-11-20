package domain_discovery

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/subfinderx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
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
	dnsWorkers      int      // concurrent subdomain lookups (DNS_RESOLVE_CONCURRENCY)
	recheckServers  []string // public resolvers for a root that "does not exist" (DNS_RECHECK_RESOLVERS); nil = off
	// lookupIP replaces the system resolver in tests; nil = the system resolver.
	lookupIP func(ctx context.Context, network, host string) ([]net.IP, error)
}

func NewService(redisClient *redis.Client, logger *zap.Logger) (*Service, error) {
	subfinderClient, err := subfinderx.NewClient(logger)
	if err != nil {
		return nil, err
	}
	dnsWorkers := config.GetEnvInt(config.EnvDNSResolveConcurrency, defaultDNSResolveConcurrency)
	if dnsWorkers < 1 {
		dnsWorkers = defaultDNSResolveConcurrency
	}
	recheckServers := recheckResolversFromEnv()
	logger.Info("Domain discovery configured",
		zap.Int("dns_resolve_concurrency", dnsWorkers),
		zap.Strings("dns_recheck_resolvers", recheckServers),
	)
	return &Service{
		redis:           redisClient,
		logger:          logger,
		subfinderClient: subfinderClient,
		tracer:          otel.Tracer("domain-discovery"),
		dnsWorkers:      dnsWorkers,
		recheckServers:  recheckServers,
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
	// rootReason is the degraded reason for the root lookup itself ("" = fine).
	rootReason := ""
	if s.isDomain(job.Host) {
		// A root domain that does not resolve is still recorded (without an
		// IP) so subdomain enumeration and parent links keep working.
		ips, err := s.resolveIPs(ctx, job.Host, true)
		if err != nil && ctx.Err() == nil {
			rootReason = shared.ScanDegradedDNSFailures
			if !isLookupFailure(err) {
				// "Not found" may be a fact or a resolver that refused upstream (Docker's
				// embedded DNS reports that as NXDOMAIN). Public resolvers decide.
				rootReason = rootNotFoundReason(ctx, job.Host, s.recheckServers)
			}
			s.logger.Warn("Root domain did not resolve",
				zap.String("trace_id", job.TraceID),
				zap.String("org_id", job.OrgID),
				zap.String("host", job.Host),
				zap.String("degraded_reason", rootReason),
				zap.Error(err),
			)
		}
		if err == nil {
			// Reject domains with any private/reserved answer to prevent SSRF
			// against internal infrastructure via DNS.
			ip, checkErr := selectPublicIP(ips)
			if checkErr != nil {
				s.logger.Warn("Blocking domain job: resolves to private IP",
					zap.String("trace_id", job.TraceID),
					zap.String("org_id", job.OrgID),
					zap.String("host", job.Host),
					zap.Error(checkErr),
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
	// A domain that does not exist has no subdomains to enumerate.
	names, failures := 0, 0
	enumFailed := false
	if job.ParentID == nil && job.Port == nil && s.isDomain(job.Host) && rootReason != shared.ScanDegradedRootNXDOMAIN {
		var err error
		names, failures, err = s.discoverSubdomains(ctx, job.TraceID, job.ScanID, job.OrgID, job.Host)
		if err != nil {
			// Cut off by shutdown: return the error so the job is not ACKed as complete.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			enumFailed = true
			s.logger.Error("subfinder subdomain discovery failed",
				zap.String("host", job.Host),
				zap.Error(err),
			)
		}
	}

	reason := degradedReason(rootReason, enumFailed, names, failures)
	if reason == "" {
		return nil
	}
	s.logger.Warn("Domain discovery incomplete; the scan will leave this asset's findings open",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("asset_id", job.AssetID),
		zap.String("host", job.Host),
		zap.String("degraded_reason", reason),
		zap.Int("names", names),
		zap.Int("lookup_failures", failures),
	)
	// Published before the job is ACKed, so the scan cannot read as drained before
	// ingestion has recorded it.
	return s.publishFinding(ctx, shared.DiscoveryFinding{
		TraceID:   job.TraceID,
		ScanID:    job.ScanID,
		OrgID:     job.OrgID,
		Source:    "subfinder",
		Host:      job.Host,
		Timestamp: time.Now(),
		Degraded: &shared.DegradedAsset{
			AssetID: job.AssetID,
			Domain:  job.Host,
			Reason:  reason,
		},
	})
}

// discoverSubdomains uses subfinder to discover and publish subdomain findings. It returns
// the number of names it looked up and how many of those lookups failed (isLookupFailure).
func (s *Service) discoverSubdomains(ctx context.Context, traceID string, scanID *string, orgID, domain string) (int, int, error) {
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
		return 0, 0, err
	}

	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	span.SetAttributes(attribute.Int("subdomain.count", len(subdomains)))

	if len(subdomains) == 0 {
		s.logger.Info("No subdomains discovered", zap.String("domain", domain))
		return 0, 0, nil
	}

	now := time.Now()
	// Generate parent domain ID (org-scoped)
	parentDomainID := shared.GenerateDomainID(orgID, domain)

	// Build the full names, skipping empty strings, wildcards and duplicates.
	seen := make(map[string]bool, len(subdomains))
	names := make([]string, 0, len(subdomains))
	for _, subdomainName := range subdomains {
		if subdomainName == "" || subdomainName == "*" {
			continue
		}
		fullSubdomain := subdomainName
		if !contains(subdomainName, domain) {
			fullSubdomain = subdomainName + "." + domain
		}
		if !seen[fullSubdomain] {
			seen[fullSubdomain] = true
			names = append(names, fullSubdomain)
		}
	}

	// Resolve in parallel and publish each name as soon as it resolves. Names that do not
	// resolve are dropped (passive sources return many stale names, and an unresolved name
	// could later be pointed at an internal address), and so are names with a private answer.
	var published, publishFailed atomic.Int64
	log := s.logger.With(zap.String("trace_id", traceID), zap.String("org_id", orgID))
	lookup := func(ctx context.Context, host string) ([]net.IP, error) {
		// Passive sources return many stale names: a clean NXDOMAIN is final, not retried.
		return s.resolveIPs(ctx, host, false)
	}
	failures, err := resolvePublic(ctx, names, s.dnsWorkers, lookup, func(host, ip string) {
		if err := s.publishFinding(ctx, shared.DiscoveryFinding{
			DiscoveryID: shared.GenerateSubdomainID(orgID, host),
			AssetType:   shared.AssetTypeSubdomain,
			TraceID:     traceID,
			ScanID:      scanID,
			OrgID:       orgID,
			Source:      "subfinder",
			ParentID:    &parentDomainID,
			Host:        host,
			IP:          &ip,
			Status:      shared.AssetStatusActive,
			Timestamp:   now,
		}); err != nil {
			publishFailed.Add(1)
			s.logger.Error("Failed to publish subdomain finding",
				zap.String("subdomain", host),
				zap.Error(err),
			)
			return
		}
		published.Add(1)
		s.logger.Info("Published subdomain finding", zap.String("subdomain", host))
	}, log)

	log.Info("Subdomain resolution finished",
		zap.String("domain", domain),
		zap.Int("names", len(names)),
		zap.Int64("published", published.Load()),
		zap.Int64("publish_failed", publishFailed.Load()),
		zap.Int("lookup_failures", failures),
		zap.Int("dns_resolve_concurrency", s.dnsWorkers),
		zap.Duration("duration", time.Since(now)),
		zap.Bool("cancelled", err != nil),
	)
	span.SetAttributes(attribute.Int64("subdomain.published", published.Load()))
	return len(names), failures, err
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

// selectPublicIP checks every resolved address against the shared SSRF guard
// and returns the address to record: the first IPv4 answer, or the first
// answer when there is no IPv4 one.
func selectPublicIP(ips []net.IP) (string, error) {
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses")
	}
	if err := shared.CheckPublicIPs(ips); err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return ips[0].String(), nil
}

// resolveIPs resolves a domain name to all of its A and AAAA addresses.
// Retries up to dnsRetryAttempts times with dnsRetryDelay between attempts
// to handle transient DNS failures (timeout, SERVFAIL, refused). A clean "not found"
// is retried only when retryNotFound is set (the root domain).
func (s *Service) resolveIPs(ctx context.Context, domain string, retryNotFound bool) ([]net.IP, error) {
	lookupIP := s.lookupIP
	if lookupIP == nil {
		lookupIP = (&net.Resolver{}).LookupIP
	}
	var lastErr error

	for attempt := 1; attempt <= dnsRetryAttempts; attempt++ {
		ips, err := lookupIP(ctx, "ip", domain)
		if err == nil && len(ips) > 0 {
			if attempt > 1 {
				s.logger.Info("DNS resolution succeeded after retry",
					zap.String("domain", domain),
					zap.Int("attempt", attempt),
				)
			}
			return ips, nil
		}

		if err != nil {
			lastErr = err
		} else {
			// An empty answer is a clean "no address", not a resolver failure.
			lastErr = &net.DNSError{Err: "no IP addresses found", Name: domain, IsNotFound: true}
		}

		s.logger.Debug("DNS resolution attempt failed",
			zap.String("domain", domain),
			zap.Int("attempt", attempt),
			zap.Int("max_attempts", dnsRetryAttempts),
			zap.Error(lastErr),
		)

		if !retryNotFound && !isLookupFailure(lastErr) {
			break
		}
		if attempt < dnsRetryAttempts {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(dnsRetryDelay):
			}
		}
	}

	return nil, lastErr
}
