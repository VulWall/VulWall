package discovery_enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/config"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// Consumer consumes discovery results from both domain and IP streams
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new discovery enrichment consumer
func NewConsumer(redisClient *redis.Client, cfg *config.Config, logger *zap.Logger) (*Consumer, error) {
	service, err := NewService(redisClient, cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}, nil
}

// Start begins consuming messages from both discovery streams in parallel
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting discovery enrichment consumer (dual stream)")

	// Create consumer groups for both streams
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDomainDiscoveryResults, GroupDiscoveryEnrichmentDomain); err != nil {
		return fmt.Errorf("failed to create domain consumer group: %w", err)
	}

	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupDiscoveryEnrichmentIP); err != nil {
		return fmt.Errorf("failed to create IP consumer group: %w", err)
	}

	// Use errgroup to run both consumers in parallel
	g, ctx := errgroup.WithContext(ctx)

	// Consumer 1: domain_discovery_results
	g.Go(func() error {
		return c.consumeDomainResults(ctx)
	})

	// Consumer 2: ip_discovery_results
	g.Go(func() error {
		return c.consumeIPResults(ctx)
	})

	// Wait for both consumers
	return g.Wait()
}

// consumeDomainResults consumes from domain_discovery_results stream
func (c *Consumer) consumeDomainResults(ctx context.Context) error {
	consumerName := "discovery-enrichment-domain-" + uuid.New().String()

	c.logger.Info("Started domain results consumer",
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamDomainDiscoveryResults),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Domain results consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupDiscoveryEnrichmentDomain,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainDiscoveryResults, ">"},
				Count:    1,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
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
					c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupDiscoveryEnrichmentDomain, message.ID)
				}
			}
		}
	}
}

// consumeIPResults consumes from ip_discovery_results stream
func (c *Consumer) consumeIPResults(ctx context.Context) error {
	consumerName := "discovery-enrichment-ip-" + uuid.New().String()

	c.logger.Info("Started IP results consumer",
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamIPDiscoveryResults),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("IP results consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupDiscoveryEnrichmentIP,
				Consumer: consumerName,
				Streams:  []string{shared.StreamIPDiscoveryResults, ">"},
				Count:    1,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.logger.Error("Failed to read from IP stream", zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleIPMessage(ctx, message); err != nil {
						c.logger.Error("Failed to process IP message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamIPDiscoveryResults, GroupDiscoveryEnrichmentIP, message.ID)
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

	// Validate org_id
	if finding.OrgID == "" {
		c.logger.Warn("Skipping finding without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Validate asset_type
	if finding.AssetType == "" {
		c.logger.Warn("Skipping finding without asset_type",
			zap.String("message_id", message.ID),
			zap.String("discovery_id", finding.DiscoveryID),
		)
		return nil
	}

	// Skip if port (shouldn't happen in domain_discovery_results)
	if finding.AssetType == shared.AssetTypePort {
		c.logger.Debug("Skipping port asset from domain stream",
			zap.String("discovery_id", finding.DiscoveryID),
		)
		return nil
	}

	// Build enrichment target
	var ip string
	if finding.IP != nil {
		ip = *finding.IP
	}

	target := EnrichmentTarget{
		DiscoveryID: finding.DiscoveryID,
		AssetType:   finding.AssetType,
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
		Host:        finding.Host,
		IP:          ip,
	}

	// Process enrichment
	return c.service.ProcessEnrichment(ctx, target)
}

// handleIPMessage processes a single IP discovery finding message
func (c *Consumer) handleIPMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse IP discovery finding
	var finding shared.IPDiscoveryFinding
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

	// Validate asset_type
	if finding.AssetType == "" {
		c.logger.Warn("Skipping finding without asset_type",
			zap.String("message_id", message.ID),
			zap.String("discovery_id", finding.DiscoveryID),
		)
		return nil
	}

	// Only enrich IPs, skip ports
	if finding.AssetType != shared.AssetTypeIP {
		c.logger.Debug("Skipping non-IP asset from IP stream",
			zap.String("asset_type", finding.AssetType),
			zap.String("discovery_id", finding.DiscoveryID),
		)
		return nil
	}

	// Build enrichment target
	target := EnrichmentTarget{
		DiscoveryID: finding.DiscoveryID,
		AssetType:   finding.AssetType,
		TraceID:     finding.TraceID,
		ScanID:      finding.ScanID,
		OrgID:       finding.OrgID,
		Host:        "",  // No host for raw IPs
		IP:          finding.IP,
	}

	// Process enrichment
	return c.service.ProcessEnrichment(ctx, target)
}
