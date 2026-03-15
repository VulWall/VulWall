package email_security_scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer represents the email security scanner consumer
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new email security scanner consumer
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
	c.logger.Info("Starting EmailSecurityScanner consumer")

	// Create consumer group for domain scan triggers (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupEmailSecurityScanner); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}
	redisx.CleanupStaleConsumers(ctx, c.redis, shared.StreamDomainScanTriggers, GroupEmailSecurityScanner, c.logger)

	// Generate unique consumer name
	consumerName := fmt.Sprintf("email-security-scanner-%s", uuid.New().String())

	c.logger.Info("Consumer name generated",
		zap.String("consumer", consumerName),
	)

	return c.processMessages(ctx, consumerName)
}

// processMessages processes messages from domain_scan_triggers stream
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	c.logger.Info("Starting domain scan triggers consumer",
		zap.String("stream", shared.StreamDomainScanTriggers),
		zap.String("group", GroupEmailSecurityScanner),
		zap.String("consumer", consumerName),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Consumer shutting down")
			return ctx.Err()
		default:
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupEmailSecurityScanner,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainScanTriggers, ">"},
				Count:    ConsumerBatchSize,
				Block:    0,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				c.logger.Error("Failed to read from domain scan triggers stream", zap.Error(err))
				continue
			}

			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleMessage(ctx, message); err != nil {
						c.logger.Error("Failed to handle message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					c.redis.XAck(ctx, shared.StreamDomainScanTriggers, GroupEmailSecurityScanner, message.ID)
				}
			}
		}
	}
}

// handleMessage handles a single message from domain_scan_triggers
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("invalid message format: missing data field")
	}

	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal discovery finding: %w", err)
	}

	// Extract trace context
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Only process domains and subdomains
	if finding.AssetType != shared.AssetTypeDomain && finding.AssetType != shared.AssetTypeSubdomain {
		c.logger.Debug("Skipping non-domain asset",
			zap.String("asset_type", finding.AssetType),
			zap.String("host", finding.Host),
		)
		return nil
	}

	scanTarget := ScanTarget{
		Target:      finding.Host,
		AssetType:   finding.AssetType,
		DiscoveryID: finding.DiscoveryID,
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	return c.service.ProcessDiscovery(ctx, scanTarget)
}
