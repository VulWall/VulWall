package ai_finding_enricher

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
	"go.uber.org/zap"
)

// Consumer consumes AI enrichment jobs from Redis and generates AI recommendations
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new AI finding enricher consumer
func NewConsumer(redisClient *redis.Client, service *Service, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from the ai_enrichment_queue stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting AI finding enricher consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamAIEnrichmentQueue, GroupAIFindingEnricher); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Generate unique consumer name for this worker
	consumerName := "ai-enricher-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("group", GroupAIFindingEnricher),
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamAIEnrichmentQueue),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

// processMessages is the main message processing loop
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Context cancelled, shutting down AI enricher consumer")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupAIFindingEnricher,
				Consumer: consumerName,
				Streams:  []string{shared.StreamAIEnrichmentQueue, ">"},
				Count:    int64(ConsumerBatchSize),
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
					c.redis.XAck(ctx, shared.StreamAIEnrichmentQueue, GroupAIFindingEnricher, message.ID)
				}
			}
		}
	}
}

// handleMessage processes a single AI enrichment job message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse AI enrichment job
	var job shared.AIEnrichmentJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return fmt.Errorf("failed to unmarshal AI enrichment job: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, job.TraceContext)

	// Validate required fields
	if job.OrgID == "" {
		c.logger.Warn("Skipping job without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	if job.FindingType == "" || job.Title == "" {
		c.logger.Warn("Skipping job with missing composite key fields",
			zap.String("message_id", message.ID),
			zap.String("finding_type", job.FindingType),
			zap.String("title", job.Title),
		)
		return nil
	}

	// Process the job (jobs are pre-filtered by findings_ingestion)
	return c.service.ProcessJob(ctx, job)
}
