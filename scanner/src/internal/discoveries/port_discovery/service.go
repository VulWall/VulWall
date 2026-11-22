package port_discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/port_discovery/services"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	redis      *redis.Client
	logger     *zap.Logger
	tcpScanner *services.Scanner
	tracer     trace.Tracer
}

func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:      redisClient,
		logger:     logger,
		tcpScanner: services.NewScanner(),
		tracer:     otel.Tracer("port-discovery"),
	}
}

// cdnPTRSuffixes is a list of known CDN/shared-edge PTR suffixes.
// ponytail: PTR heuristic; misses CDN IPs with generic or no PTR.
// Upgrade path: wire internal/active_recon/discovery_enrichment/cloud.Detector for CIDR-accurate detection.
var cdnPTRSuffixes = []string{
	"cloudfront.net",
	"cloudflare.com",
	"cloudflare.net",
	"akamai.net",
	"akamaihd.net",
	"akamaized.net",
	"akamaiedge.net",
	"akamaitechnologies.com",
	"edgekey.net",
	"fastly.net",
	"incapdns.net",
	"azureedge.net",
	"googleusercontent.com",
}

// ProcessJob processes an IP discovery job using the TCP scanner for all IPs.
// Domain-resolved IPs are first checked against known CDN/shared-edge PTR suffixes
// and skipped to avoid attributing shared infrastructure ports to the wrong customer.
func (s *Service) ProcessJob(ctx context.Context, job shared.IPDiscoveryJob) error {
	ctx, span := s.tracer.Start(ctx, "scan_ports",
		trace.WithAttributes(
			attribute.String("org.id", job.OrgID),
			attribute.String("trace.id", job.TraceID),
			attribute.String("ip", job.IP),
		),
	)
	defer span.End()

	s.logger.Info("Processing IP discovery job",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("ip", job.IP),
	)

	// For domain-resolved IPs: skip CDN/shared-edge infrastructure via PTR lookup.
	// Direct-IP assets (TargetDomain == "") scan unconditionally.
	if job.TargetDomain != "" && s.isCDNByPTR(ctx, job.IP) {
		s.logger.Info("Skipping port scan — IP is CDN infrastructure (PTR match)",
			zap.String("trace_id", job.TraceID),
			zap.String("ip", job.IP),
			zap.String("target_domain", job.TargetDomain),
		)
		span.SetAttributes(
			attribute.String("skip_reason", "cdn_ptr_match"),
			attribute.Bool("scan.success", true),
		)
		span.SetStatus(codes.Ok, "")
		return nil
	}

	span.SetAttributes(
		attribute.String("source", "port_discovery"),
		attribute.Bool("scan.success", true),
	)
	span.SetStatus(codes.Ok, "")
	return s.processTCPScan(ctx, job)
}

// isCDNByPTR performs a reverse DNS (PTR) lookup and returns true if any PTR record
// matches a known CDN suffix. Returns false on lookup failure (err-open: safe to scan).
// Uses a 3s timeout to avoid stalling the serial worker on slow resolvers.
func (s *Service) isCDNByPTR(ctx context.Context, ip string) bool {
	ptrCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	ptrs, err := resolver.LookupAddr(ptrCtx, ip)
	if err != nil || len(ptrs) == 0 {
		return false
	}
	for _, ptr := range ptrs {
		ptr = strings.ToLower(strings.TrimSuffix(ptr, "."))
		for _, suffix := range cdnPTRSuffixes {
			if strings.HasSuffix(ptr, suffix) {
				s.logger.Debug("CDN PTR match",
					zap.String("ip", ip),
					zap.String("ptr", ptr),
					zap.String("suffix", suffix),
				)
				return true
			}
		}
	}
	return false
}

// processTCPScan performs TCP port scanning for the given IP.
func (s *Service) processTCPScan(ctx context.Context, job shared.IPDiscoveryJob) error {
	// Determine which ports to scan
	portsToScan := CommonPorts
	// TODO: In the future, support custom port ranges from job.PortRange

	// Scan all ports and filter to open ones
	openPorts := s.tcpScanner.ScanPortsFiltered(ctx, job.IP, portsToScan)
	if ctx.Err() != nil {
		return ctx.Err() // shutdown cut the scan off: leave the job pending
	}

	s.logger.Info("TCP port scan completed",
		zap.String("trace_id", job.TraceID),
		zap.String("ip", job.IP),
		zap.Int("total_scanned", len(portsToScan)),
		zap.Int("open_ports", len(openPorts)),
	)

	// Publish findings for each open port
	now := time.Now()
	for _, portResult := range openPorts {
		// Generate deterministic ID for this port (org-scoped)
		portID := shared.GeneratePortID(job.OrgID, job.IP, portResult.Port, shared.ProtocolTCP)

		// Set banner if available
		var banner *string
		if portResult.Banner != "" {
			banner = &portResult.Banner
		}

		finding := shared.IPDiscoveryFinding{
			DiscoveryID:  portID,
			AssetType:    shared.AssetTypePort,
			TraceID:      job.TraceID,
			ScanID:       job.ScanID,
			OrgID:        job.OrgID,
			AssetID:      job.AssetID,
			ParentID:     job.ParentID,
			Source:       "port_discovery",
			IP:           job.IP,
			TargetDomain: job.TargetDomain,
			Port:         portResult.Port,
			Protocol:     shared.ProtocolTCP,
			Status:       shared.AssetStatusActive,
			Banner:       banner,
			Timestamp:    now,
		}

		if err := s.publishFinding(ctx, finding); err != nil {
			// Returned, so the job is retried: a port that did not reach the pipeline
			// must not read as closed.
			return fmt.Errorf("publish port %d of %s: %w", portResult.Port, job.IP, err)
		}

		s.logger.Debug("Published TCP port finding",
			zap.String("trace_id", job.TraceID),
			zap.String("ip", job.IP),
			zap.Int("port", portResult.Port),
		)
	}

	// If no open ports found, still log completion
	if len(openPorts) == 0 {
		s.logger.Info("No open ports found",
			zap.String("trace_id", job.TraceID),
			zap.String("ip", job.IP),
		)
	}

	// The port scan of this IP completed: a port of it that was open before and is not open
	// now was checked and found closed. A scan that found no port open at all is no
	// evidence: the IP may be dropping the scanner's packets (a block looks like "all
	// closed"). After the open ports, before the ACK.
	if len(openPorts) == 0 {
		return nil
	}
	msg := shared.CoverageMessage(job.OrgID, job.ScanID, job.TraceID, shared.ScanCoverage{
		Source:      shared.CoverageSourcePortDiscovery,
		DiscoveryID: shared.GenerateIPID(job.OrgID, job.IP),
		Target:      job.IP,
		Status:      shared.CoverageOK,
	})
	msg.TraceContext = telemetry.InjectTraceContext(ctx)
	return redisx.PublishToStream(ctx, s.redis, shared.StreamSecurityFindings, msg, 0)
}

// publishFinding publishes a port discovery finding to the IP discovery results stream
func (s *Service) publishFinding(ctx context.Context, finding shared.IPDiscoveryFinding) error {
	// Inject trace context for span linking across service boundaries
	finding.TraceContext = telemetry.InjectTraceContext(ctx)

	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming after all consumers process
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamIPDiscoveryResults, finding, 0); err != nil {
		s.logger.Error("Failed to publish finding to stream",
			zap.String("stream", shared.StreamIPDiscoveryResults),
			zap.Error(err),
		)
		return err
	}

	return nil
}
