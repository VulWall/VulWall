package kb_ingestion

import (
	"context"
	"encoding/json"
	"errors"
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

// Consumer consumes KB generation results from Redis and persists them to MongoDB
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new KB ingestion consumer
func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	service := NewService(db, logger)
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from the kb_generation_results stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting KB ingestion consumer")

	// Ensure indexes on knowledge_base collection
	if err := EnsureIndexes(ctx, c.service.db, c.logger); err != nil {
		c.logger.Warn("Failed to ensure KB indexes", zap.Error(err))
	}

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamKBGenerationResults, GroupKBIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Generate unique consumer name for this worker
	consumerName := "kb-ingestion-worker-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("group", GroupKBIngestion),
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamKBGenerationResults),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

// permanentError wraps errors that should not be retried (e.g., invalid message data).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// processMessages is the main message processing loop
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Context cancelled, shutting down KB ingestion consumer")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupKBIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamKBGenerationResults, ">"},
				Count:    shared.IngestionBatchSize,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
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
						var permErr *permanentError
						if errors.As(err, &permErr) {
							c.logger.Error("Permanently invalid message, acknowledging to prevent retry loop",
								zap.String("message_id", message.ID),
								zap.Error(err),
							)

							data, _ := message.Values["data"].(string)
							if dlErr := redisx.PublishDeadLetter(ctx, c.redis, shared.StreamKBGenerationResults, GroupKBIngestion, message.ID, data, err); dlErr != nil {
								c.logger.Warn("Failed to publish to dead-letter stream",
									zap.String("message_id", message.ID),
									zap.Error(dlErr),
								)
							}

							_ = c.redis.XAck(ctx, shared.StreamKBGenerationResults, GroupKBIngestion, message.ID).Err()
						} else {
							c.logger.Error("Failed to process message, leaving unacknowledged for retry",
								zap.String("message_id", message.ID),
								zap.Error(err),
							)
						}
						continue
					}

					// Only acknowledge on success
					if err := c.redis.XAck(ctx, shared.StreamKBGenerationResults, GroupKBIngestion, message.ID).Err(); err != nil {
						c.logger.Warn("Failed to acknowledge message — will be redelivered",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}
				}
			}
		}
	}
}

// handleMessage processes a single KB generation result message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return &permanentError{err: fmt.Errorf("message data is not a string")}
	}

	// Parse KB generation result
	var result shared.KBGenerationResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return &permanentError{err: fmt.Errorf("failed to unmarshal KB result: %w", err)}
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, result.TraceContext)

	// Process the result
	return c.service.ProcessEntry(ctx, result)
}
