package port_discovery

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/discoveries/port_discovery/scanner"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

type Service struct {
	redis   *redis.Client
	logger  *zap.Logger
	scanner *scanner.Scanner
}

func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:   redisClient,
		logger:  logger,
		scanner: scanner.NewScanner(),
	}
}

// ProcessJob processes an IP discovery job by scanning common ports
func (s *Service) ProcessJob(ctx context.Context, job shared.IPDiscoveryJob) error {
	s.logger.Info("Processing IP discovery job",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("ip", job.IP),
	)

	// Determine which ports to scan
	portsToScan := CommonPorts
	// TODO: In the future, support custom port ranges from job.PortRange

	// Scan all ports and filter to open ones
	openPorts := s.scanner.ScanPortsFiltered(ctx, job.IP, portsToScan)

	s.logger.Info("Port scan completed",
		zap.String("trace_id", job.TraceID),
		zap.String("ip", job.IP),
		zap.Int("total_scanned", len(portsToScan)),
		zap.Int("open_ports", len(openPorts)),
	)

	// Publish findings for each open port
	now := time.Now()
	for _, portResult := range openPorts {
		metadata := map[string]interface{}{
			"scan_method": "tcp_connect",
		}

		// Set banner if available
		var banner *string
		if portResult.Banner != "" {
			banner = &portResult.Banner
		}

		finding := shared.IPDiscoveryFinding{
			TraceID:   job.TraceID,
			OrgID:     job.OrgID,
			Source:    "port_discovery",
			ParentID:  job.ParentID,
			IP:        job.IP,
			Port:      portResult.Port,
			Protocol:  shared.ProtocolTCP,
			Status:    shared.AssetStatusActive,
			Banner:    banner,
			Metadata:  metadata,
			Timestamp: now,
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
	data, err := json.Marshal(finding)
	if err != nil {
		s.logger.Error("Failed to marshal finding", zap.Error(err))
		return err
	}

	_, err = s.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: shared.StreamIPDiscoveryResults,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Result()

	if err != nil {
		s.logger.Error("Failed to publish finding to stream",
			zap.String("stream", shared.StreamIPDiscoveryResults),
			zap.Error(err),
		)
		return err
	}

	return nil
}
