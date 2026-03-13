package testssl_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer consumes domain scan triggers for TLS/SSL analysis
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new testssl scanner consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) *Consumer {
	service := NewService(redisClient, logger)
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming domain scan trigger messages for TLS/SSL analysis
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting testssl scanner consumer")

	// Create consumer group for domain trigger stream (start from latest — triggers are ephemeral)
	if err := redisx.CreateConsumerGroupFromLatest(ctx, c.redis, shared.StreamDomainScanTriggers, GroupTestSSLScanner); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	// Generate unique consumer name for this worker
	consumerName := "testssl-domain-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("consumer", consumerName),
	)

	// Process domain scan triggers (testssl only runs on domain/subdomain targets)
	return c.processDomainMessages(ctx, consumerName)
}

// processDomainMessages processes messages from domain_discovery_results stream
func (c *Consumer) processDomainMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Domain consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from domain discovery results stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupTestSSLScanner,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainScanTriggers, ">"},
				Count:    ConsumerBatchSize,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					// No messages available
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.logger.Error("Failed to read from domain stream", zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleDomainMessage(ctx, message); err != nil {
						c.logger.Error("Failed to process domain message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamDomainScanTriggers, GroupTestSSLScanner, message.ID)
				}
			}
		}
	}
}

// handleDomainMessage processes a single domain discovery finding message
func (c *Consumer) handleDomainMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse discovery finding
	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal finding: %w", err)
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

	// testssl needs a hostname for proper SNI — always use host:443
	if finding.Host == "" {
		c.logger.Warn("Skipping finding without host",
			zap.String("message_id", message.ID),
		)
		return nil
	}
	target := fmt.Sprintf("%s:443", finding.Host)

	// Create scan target - use discovery ID directly from finding
	// Discovery services always include this ID
	scanTarget := ScanTarget{
		Target:      target,
		AssetType:   finding.AssetType,   // Asset type (domain, subdomain, ip, port)
		DiscoveryID: finding.DiscoveryID, // Always present from discovery services
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,      // Optional: scan identifier for linking to UI scans
		OrgID:       finding.OrgID,
	}

	// Process the scan
	return c.service.ProcessDiscovery(ctx, scanTarget)
}

