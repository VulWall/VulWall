package port_discovery

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/shodan"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/discoveries/port_discovery/services"
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
	tcpScanner   *services.Scanner
	tracer       trace.Tracer
}

func NewService(redisClient *redis.Client, shodanAPIKey string, logger *zap.Logger) *Service {
	return &Service{
		redis:        redisClient,
		logger:       logger,
		shodanClient: shodan.NewClient(shodanAPIKey, logger),
		tcpScanner:   services.NewScanner(),
		tracer:       otel.Tracer("port-discovery"),
	}
}

// ProcessJob processes an IP discovery job
// Primary: Shodan Host API for richer port/service data
// Fallback: TCP scanner when Shodan fails (404, rate limit, timeout)
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

	// Try Shodan first
	hostInfo, err := s.shodanClient.GetHostInfo(ctx, job.IP)
	if err == nil && hostInfo != nil {
		// Shodan succeeded - publish findings with source="shodan"
		span.SetAttributes(attribute.String("source", "shodan"))
		return s.publishShodanFindings(ctx, job, hostInfo)
	}

	// Log why Shodan failed
	if err != nil {
		s.logger.Debug("Shodan lookup failed, falling back to TCP scan",
			zap.String("ip", job.IP),
			zap.Error(err),
		)
		span.SetAttributes(attribute.String("shodan.error", err.Error()))
	} else {
		s.logger.Debug("IP not found in Shodan, falling back to TCP scan",
			zap.String("ip", job.IP),
		)
		span.SetAttributes(attribute.String("shodan.error", "not_found"))
	}

	// Fallback to TCP scanner
	span.SetAttributes(attribute.String("source", "port_discovery"))
	return s.processTCPScan(ctx, job)
}

// publishShodanFindings publishes port findings from Shodan Host API response
func (s *Service) publishShodanFindings(ctx context.Context, job shared.IPDiscoveryJob, hostInfo *shodan.HostInfo) error {
	s.logger.Info("Publishing Shodan port findings",
		zap.String("trace_id", job.TraceID),
		zap.String("ip", job.IP),
		zap.Int("ports_found", len(hostInfo.Data)),
	)

	now := time.Now()

	// Publish each port from Shodan data
	for _, portData := range hostInfo.Data {
		protocol := portData.Transport
		if protocol == "" {
			protocol = shared.ProtocolTCP
		}

		// Generate deterministic ID for this port (org-scoped)
		portID := shared.GeneratePortID(job.OrgID, job.IP, portData.Port, protocol)

		// Extract service information
		var serviceName, product, version, banner *string
		if portData.Product != "" {
			product = &portData.Product
			serviceName = &portData.Product // Use product as service name if available
		}
		if portData.Version != "" {
			version = &portData.Version
		}
		if portData.Banner != "" {
			// Truncate banner to prevent storage bloat (max 2KB)
			truncated := truncateBanner(portData.Banner, 2048)
			banner = &truncated
		}

		// Build metadata with Shodan-specific info
		metadata := make(map[string]interface{})
		if portData.HTTP != nil {
			metadata["http"] = map[string]interface{}{
				"server": portData.HTTP.Server,
				"title":  portData.HTTP.Title,
				"status": portData.HTTP.StatusCode,
			}
		}
		if portData.SSL != nil {
			metadata["ssl"] = map[string]interface{}{
				"versions": portData.SSL.Versions,
			}
			if portData.SSL.Cert != nil {
				metadata["ssl"].(map[string]interface{})["cert_expired"] = portData.SSL.Cert.Expired
				metadata["ssl"].(map[string]interface{})["cert_expires"] = portData.SSL.Cert.Expires
			}
		}

		finding := shared.IPDiscoveryFinding{
			DiscoveryID: portID,
			AssetType:   shared.AssetTypePort,
			TraceID:     job.TraceID,
			ScanID:      job.ScanID,
			OrgID:       job.OrgID,
			Source:      "shodan",
			ParentID:    job.ParentID,
			IP:          job.IP,
			Port:        portData.Port,
			Protocol:    protocol,
			Status:      shared.AssetStatusActive,
			Banner:      banner,
			ServiceName: serviceName,
			Product:     product,
			Version:     version,
			Metadata:    metadata,
			Timestamp:   now,
		}

		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish Shodan port finding",
				zap.String("trace_id", job.TraceID),
				zap.String("ip", job.IP),
				zap.Int("port", portData.Port),
				zap.Error(err),
			)
			continue
		}

		s.logger.Debug("Published Shodan port finding",
			zap.String("trace_id", job.TraceID),
			zap.String("ip", job.IP),
			zap.Int("port", portData.Port),
			zap.String("product", portData.Product),
		)
	}

	s.logger.Info("Shodan port discovery completed",
		zap.String("trace_id", job.TraceID),
		zap.String("ip", job.IP),
		zap.Int("ports_published", len(hostInfo.Data)),
	)

	return nil
}

// processTCPScan performs TCP port scanning as fallback
func (s *Service) processTCPScan(ctx context.Context, job shared.IPDiscoveryJob) error {
	// Determine which ports to scan
	portsToScan := CommonPorts
	// TODO: In the future, support custom port ranges from job.PortRange

	// Scan all ports and filter to open ones
	openPorts := s.tcpScanner.ScanPortsFiltered(ctx, job.IP, portsToScan)

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
			DiscoveryID: portID,
			AssetType:   shared.AssetTypePort,
			TraceID:     job.TraceID,
			ScanID:      job.ScanID,
			OrgID:       job.OrgID,
			Source:      "port_discovery",
			IP:          job.IP,
			Port:        portResult.Port,
			Protocol:    shared.ProtocolTCP,
			Status:      shared.AssetStatusActive,
			Banner:      banner,
			Timestamp:   now,
		}

		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish TCP port finding",
				zap.String("trace_id", job.TraceID),
				zap.String("ip", job.IP),
				zap.Int("port", portResult.Port),
				zap.Error(err),
			)
			continue
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

	return nil
}

// publishFinding publishes a port discovery finding to the IP discovery results stream
func (s *Service) publishFinding(ctx context.Context, finding shared.IPDiscoveryFinding) error {
	// Inject trace context for span linking across service boundaries
	finding.TraceContext = telemetry.InjectTraceContext(ctx)

	// Use shared publisher utility with MAXLEN=10000 to prevent unbounded growth
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamIPDiscoveryResults, finding, 10000); err != nil {
		s.logger.Error("Failed to publish finding to stream",
			zap.String("stream", shared.StreamIPDiscoveryResults),
			zap.Error(err),
		)
		return err
	}

	return nil
}

// truncateBanner truncates banner to specified max length
func truncateBanner(banner string, maxLen int) string {
	if len(banner) <= maxLen {
		return banner
	}
	return banner[:maxLen]
}
