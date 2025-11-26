package port_discovery

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/discoveries/port_discovery/services"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	redis   *redis.Client
	logger  *zap.Logger
	scanner *services.Scanner
	tracer  trace.Tracer
}

func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:   redisClient,
		logger:  logger,
		scanner: services.NewScanner(),
		tracer:  otel.Tracer("port-discovery"),
	}
}

// ProcessJob processes an IP discovery job by scanning common ports
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

	// Determine which ports to scan
	portsToScan := CommonPorts
	// TODO: In the future, support custom port ranges from job.PortRange

	span.SetAttributes(attribute.Int("ports.to_scan", len(portsToScan)))

	// Scan all ports and filter to open ones
	openPorts := s.scanner.ScanPortsFiltered(ctx, job.IP, portsToScan)

	span.SetAttributes(attribute.Int("ports.open", len(openPorts)))

	s.logger.Info("Port scan completed",
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
			ScanID:      job.ScanID, // Pass through scan_id
			OrgID:       job.OrgID,
			Scanner:     "port_discovery",
			IP:          job.IP,
			Port:        portResult.Port,
			Protocol:    shared.ProtocolTCP,
			Status:      shared.AssetStatusActive,
			Banner:      banner,
			Timestamp:   now,
		}

		if err := s.publishFinding(ctx, finding); err != nil {
			s.logger.Error("Failed to publish port finding",
				zap.String("trace_id", job.TraceID),
				zap.String("ip", job.IP),
				zap.Int("port", portResult.Port),
				zap.Error(err),
			)
			// Continue with other ports even if one fails
			continue
		}

		s.logger.Debug("Published port finding",
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
