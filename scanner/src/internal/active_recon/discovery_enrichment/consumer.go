package discovery_enrichment

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

// Consumer consumes enrichment jobs from discovery_enrichment_queue
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new discovery enrichment consumer
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

// Start begins consuming enrichment jobs from the queue
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting discovery enrichment consumer (single queue)")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDiscoveryEnrichmentQueue, GroupDiscoveryEnrichment); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	return c.consumeEnrichmentJobs(ctx)
}

// consumeEnrichmentJobs consumes from discovery_enrichment_queue stream
func (c *Consumer) consumeEnrichmentJobs(ctx context.Context) error {
	consumerName := "discovery-enrichment-" + uuid.New().String()

	c.logger.Info("Started enrichment jobs consumer",
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamDiscoveryEnrichmentQueue),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Enrichment consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupDiscoveryEnrichment,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDiscoveryEnrichmentQueue, ">"},
				Count:    ConsumerBatchSize,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.logger.Error("Failed to read from enrichment queue", zap.Error(err))
				time.Sleep(5 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleEnrichmentJob(ctx, message); err != nil {
						c.logger.Error("Failed to process enrichment job",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Acknowledge message
					c.redis.XAck(ctx, shared.StreamDiscoveryEnrichmentQueue, GroupDiscoveryEnrichment, message.ID)
				}
			}
		}
	}
}

// handleEnrichmentJob processes a single enrichment job message
func (c *Consumer) handleEnrichmentJob(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse enrichment job
	var job shared.EnrichmentJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return fmt.Errorf("failed to unmarshal enrichment job: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, job.TraceContext)

	// Validate org_id
	if job.OrgID == "" {
		c.logger.Warn("Skipping job without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Validate asset_type
	if job.AssetType == "" {
		c.logger.Warn("Skipping job without asset_type",
			zap.String("message_id", message.ID),
			zap.String("discovery_id", job.DiscoveryID),
		)
		return nil
	}

	// Process enrichment
	return c.service.ProcessEnrichment(ctx, job)
}
