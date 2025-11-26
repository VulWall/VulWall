package ai_enrichment_ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Consumer consumes AI enrichments from Redis and persists them to MongoDB
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new AI enrichment ingestion consumer
func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	service := NewService(db, logger)
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from the ai_enrichment_results stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting AI enrichment ingestion consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamAIEnrichmentResults, GroupAIEnrichmentIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Generate unique consumer name for this worker
	consumerName := "ai-enrichment-worker-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("group", GroupAIEnrichmentIngestion),
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamAIEnrichmentResults),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

// processMessages is the main message processing loop
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Context cancelled, shutting down AI enrichment ingestion consumer")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupAIEnrichmentIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamAIEnrichmentResults, ">"},
				Count:    shared.IngestionBatchSize,
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
					c.redis.XAck(ctx, shared.StreamAIEnrichmentResults, GroupAIEnrichmentIngestion, message.ID)
				}
			}
		}
	}
}

// handleMessage processes a single AI enrichment message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse AI enrichment
	var enrichment shared.AIEnrichmentFinding
	if err := json.Unmarshal([]byte(data), &enrichment); err != nil {
		return fmt.Errorf("failed to unmarshal enrichment: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, enrichment.TraceContext)

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
