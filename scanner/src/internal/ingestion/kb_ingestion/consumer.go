package kb_ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamKBGenerationResults,
		Group:          GroupKBIngestion,
		ConsumerPrefix: "kb-ingestion-worker",
		BatchSize:      shared.IngestionBatchSize,
		Handler:        c.handleMessageWithDeadLetter,
		Logger:         c.logger,
	})
}

// permanentError wraps errors that should not be retried (e.g., invalid message data).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// handleMessageWithDeadLetter wraps handleMessage with dead-letter logic.
// Permanent errors are sent to the dead-letter stream. All errors are logged
// but nil is returned so ConsumeStream handles the ACK.
func (c *Consumer) handleMessageWithDeadLetter(ctx context.Context, message redis.XMessage) error {
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
			return nil
		}

		c.logger.Error("Failed to process message",
			zap.String("message_id", message.ID),
			zap.Error(err),
		)
	}

	return nil
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
