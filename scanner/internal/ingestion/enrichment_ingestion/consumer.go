package enrichment_ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Consumer consumes enrichment findings from Redis stream
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new enrichment ingestion consumer
func NewConsumer(redis *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	service := NewService(db, redis, logger)
	return &Consumer{
		redis:   redis,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from asset_enrichment_results stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting enrichment ingestion consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDiscoveryEnrichmentResults, GroupEnrichmentIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Generate unique consumer name
	consumerName := "enrichment-ingestion-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamDiscoveryEnrichmentResults),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

// processMessages processes messages from the enrichment stream
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from enrichment stream (using "0" to get pending + new messages)
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupEnrichmentIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDiscoveryEnrichmentResults, "0"},
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
					c.redis.XAck(ctx, shared.StreamDiscoveryEnrichmentResults, GroupEnrichmentIngestion, message.ID)
				}
			}
		}
	}
}

// handleMessage processes a single enrichment message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse enrichment finding
	var enrichment shared.EnrichmentFinding
	if err := json.Unmarshal([]byte(data), &enrichment); err != nil {
		return fmt.Errorf("failed to unmarshal enrichment: %w", err)
	}

	// Validate org_id
	if enrichment.OrgID == "" {
		c.logger.Warn("Skipping enrichment without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Process the enrichment
	return c.service.ProcessEnrichment(ctx, enrichment)
}
