package waf_detector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Consumer consumes discovery results from domain discovery stream
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new WAF detector consumer
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

// Start begins consuming messages from domain discovery results stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting WAF detector consumer")

	// Create consumer group for domain discovery results
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDomainDiscoveryResults, GroupWAFDetector); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Generate unique consumer name for this worker
	consumerName := "waf-detector-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamDomainDiscoveryResults),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

// processMessages processes messages from domain_discovery_results stream
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from domain discovery results stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupWAFDetector,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainDiscoveryResults, ">"},
				Count:    1,
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
				c.logger.Error("Failed to read from stream", zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleMessage(ctx, message); err != nil {
						c.logger.Error("Failed to process message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupWAFDetector, message.ID)
				}
			}
		}
	}
}

// handleMessage processes a single domain discovery finding message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
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

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Only process domain and subdomain assets (not IPs or ports)
	// WAF detection requires HTTP(S) endpoints, which are typically domains/subdomains
	if finding.Host == "" {
		c.logger.Debug("Skipping finding without host",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Skip if it's a raw IP address without a domain
	// We want to focus on domains/subdomains that are more likely to have WAFs
	if finding.IP != nil && *finding.IP != "" && finding.Host == *finding.IP {
		c.logger.Debug("Skipping raw IP address",
			zap.String("message_id", message.ID),
			zap.String("ip", *finding.IP),
		)
		return nil
	}

	// Build target URL
	// Try HTTPS first (most modern WAFs are on HTTPS)
	targetURL := fmt.Sprintf("https://%s", finding.Host)

	// Create detection target using the discovery_id from the finding
	target := DetectionTarget{
		TargetURL:   targetURL,
		DiscoveryID: finding.DiscoveryID,
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	// Process the detection
	return c.service.ProcessDiscovery(ctx, target)
}
