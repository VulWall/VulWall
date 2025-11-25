package js_dependency_scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer represents the JSDependencyScanner consumer
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new JSDependencyScanner consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) (*Consumer, error) {
	service := NewService(redisClient, logger)

	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}, nil
}

// Start starts the consumer (domain scan triggers only - domains and subdomains)
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting JSDependencyScanner consumer")

	// Create consumer group for domain scan triggers
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDomainScanTriggers, GroupJSDependencyScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	// Generate unique consumer name
	consumerName := fmt.Sprintf("js-dependency-scanner-%s", uuid.New().String())

	c.logger.Info("Consumer name generated",
		zap.String("consumer", consumerName),
	)

	// Start domain discovery consumer
	return c.processDomainMessages(ctx, consumerName)
}

// processDomainMessages processes messages from domain_scan_triggers stream
func (c *Consumer) processDomainMessages(ctx context.Context, consumerName string) error {
	c.logger.Info("Starting domain scan triggers consumer",
		zap.String("stream", shared.StreamDomainScanTriggers),
		zap.String("group", GroupJSDependencyScanner),
		zap.String("consumer", consumerName),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Consumer shutting down")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupJSDependencyScanner,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainScanTriggers, ">"},
				Count:    ConsumerBatchSize,
				Block:    0, // Block indefinitely
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				c.logger.Error("Failed to read from domain scan triggers stream", zap.Error(err))
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleDomainMessage(ctx, message); err != nil {
						c.logger.Error("Failed to handle domain message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamDomainScanTriggers, GroupJSDependencyScanner, message.ID)
				}
			}
		}
	}
}

// handleDomainMessage handles a single message from domain_scan_triggers
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

	// Only process domains and subdomains (skip IPs and ports)
	if finding.AssetType != shared.AssetTypeDomain && finding.AssetType != shared.AssetTypeSubdomain {
		c.logger.Debug("Skipping non-domain asset",
			zap.String("asset_type", finding.AssetType),
			zap.String("host", finding.Host),
		)
		return nil
	}

	// Build target (domain or subdomain)
	target := finding.Host

	// Create scan target
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // domain or subdomain
		DiscoveryID: finding.DiscoveryID, // Use actual discovery UUID from discoveries collection
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	// Process the discovery
	return c.service.ProcessDiscovery(ctx, scanTarget)
}
