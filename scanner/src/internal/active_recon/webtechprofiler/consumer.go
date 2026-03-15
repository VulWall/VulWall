package webtechprofiler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer represents the WebTechProfiler consumer
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new WebTechProfiler consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) (*Consumer, error) {
	service, err := NewService(redisClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}, nil
}

// Start starts the dual-stream consumer (domain and IP discovery results)
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting WebTechProfiler consumer")

	// Create consumer group for domain scan triggers (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupWebTechProfiler); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	// Create consumer group for IP discovery results (start from beginning — result stream needs guaranteed delivery)
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupWebTechProfiler); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	errChan := make(chan error, 2)

	go func() {
		errChan <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
			Stream:         shared.StreamDomainScanTriggers,
			Group:          GroupWebTechProfiler,
			ConsumerPrefix: "webtechprofiler-domain",
			BatchSize:      ConsumerBatchSize,
			Handler:        c.handleDomainMessage,
			Logger:         c.logger,
		})
	}()

	go func() {
		errChan <- redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
			Stream:         shared.StreamIPDiscoveryResults,
			Group:          GroupWebTechProfiler,
			ConsumerPrefix: "webtechprofiler-ip",
			BatchSize:      ConsumerBatchSize,
			Handler:        c.handleIPMessage,
			Logger:         c.logger,
		})
	}()

	return <-errChan
}

// handleDomainMessage handles a single message from domain_discovery_results
func (c *Consumer) handleDomainMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("invalid message format: missing data field")
	}

	// Parse discovery finding
	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal discovery finding: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Build target URL
	target := finding.Host

	// Create scan target
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (domain, subdomain, ip, port)
		DiscoveryID: finding.DiscoveryID, // Use actual discovery UUID from discoveries collection
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	// Process the discovery
	return c.service.ProcessDiscovery(ctx, scanTarget)
}

// handleIPMessage handles a single message from ip_discovery_results
func (c *Consumer) handleIPMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("invalid message format: missing data field")
	}

	// Parse IP discovery finding
	var finding shared.IPDiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal IP discovery finding: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Only process web ports
	if !isWebPort(finding.Port) {
		c.logger.Debug("Skipping non-web port",
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
		)
		return nil
	}

	// Build target (IP:port)
	target := fmt.Sprintf("%s:%d", finding.IP, finding.Port)

	// Create scan target
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (port)
		DiscoveryID: finding.DiscoveryID, // Use actual discovery UUID from discoveries collection
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	// Process the discovery
	return c.service.ProcessDiscovery(ctx, scanTarget)
}
