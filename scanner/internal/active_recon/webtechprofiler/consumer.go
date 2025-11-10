package webtechprofiler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
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

	// Create consumer groups for both streams
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDomainDiscoveryResults, GroupWebTechProfiler); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupWebTechProfiler); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	// Generate unique consumer names
	domainConsumerName := fmt.Sprintf("webtechprofiler-domain-%s", uuid.New().String())
	ipConsumerName := fmt.Sprintf("webtechprofiler-ip-%s", uuid.New().String())

	c.logger.Info("Consumer names generated",
		zap.String("domain_consumer", domainConsumerName),
		zap.String("ip_consumer", ipConsumerName),
	)

	// Start both consumers concurrently
	var wg sync.WaitGroup

	// Start domain discovery consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.processDomainMessages(ctx, domainConsumerName); err != nil && err != context.Canceled {
			c.logger.Error("Domain consumer error", zap.Error(err))
		}
	}()

	// Start IP discovery consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := c.processIPMessages(ctx, ipConsumerName); err != nil && err != context.Canceled {
			c.logger.Error("IP consumer error", zap.Error(err))
		}
	}()

	c.logger.Info("Both consumers started, waiting for messages...")
	wg.Wait()

	return nil
}

// processDomainMessages processes messages from domain_discovery_results stream
func (c *Consumer) processDomainMessages(ctx context.Context, consumerName string) error {
	c.logger.Info("Starting domain discovery consumer",
		zap.String("stream", shared.StreamDomainDiscoveryResults),
		zap.String("group", GroupWebTechProfiler),
		zap.String("consumer", consumerName),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Domain consumer shutting down")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupWebTechProfiler,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainDiscoveryResults, ">"},
				Count:    10,
				Block:    0, // Block indefinitely
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				c.logger.Error("Failed to read from domain stream", zap.Error(err))
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
					c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupWebTechProfiler, message.ID)
				}
			}
		}
	}
}

// processIPMessages processes messages from ip_discovery_results stream
func (c *Consumer) processIPMessages(ctx context.Context, consumerName string) error {
	c.logger.Info("Starting IP discovery consumer",
		zap.String("stream", shared.StreamIPDiscoveryResults),
		zap.String("group", GroupWebTechProfiler),
		zap.String("consumer", consumerName),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("IP consumer shutting down")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupWebTechProfiler,
				Consumer: consumerName,
				Streams:  []string{shared.StreamIPDiscoveryResults, ">"},
				Count:    10,
				Block:    0, // Block indefinitely
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				c.logger.Error("Failed to read from IP stream", zap.Error(err))
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleIPMessage(ctx, message); err != nil {
						c.logger.Error("Failed to handle IP message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamIPDiscoveryResults, GroupWebTechProfiler, message.ID)
				}
			}
		}
	}
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
		DiscoveryID: finding.DiscoveryID, // Use actual discovery UUID from discoveries collection
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
	}

	// Process the discovery
	return c.service.ProcessDiscovery(ctx, scanTarget)
}
