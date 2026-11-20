package knowledge_base

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Consumer consumes KB generation jobs from Redis and generates knowledge base entries
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new knowledge base engine consumer
func NewConsumer(redisClient *redis.Client, service *Service, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from the kb_generation_queue stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting knowledge base engine consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamKBGenerationQueue, GroupKBEngine); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamKBGenerationQueue,
		Group:          GroupKBEngine,
		ConsumerPrefix: "kb-engine",
		BatchSize:      int64(ConsumerBatchSize),
		Handler:        c.handleMessageWithDeadLetter,
		Logger:         c.logger,
	})
}

// permanentError wraps errors that should not be retried (e.g., invalid message data).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// handleMessageWithDeadLetter wraps handleMessage with dead-letter logic and
// post-generation cooldown. The cooldown prevents hitting Anthropic's rate limit
// (30K input tokens/min) by pausing between successful generations.
func (c *Consumer) handleMessageWithDeadLetter(ctx context.Context, message redis.XMessage) error {
	if err := c.handleMessage(ctx, message); err != nil {
		var permErr *permanentError
		if errors.As(err, &permErr) {
			c.logger.Error("Permanently invalid message, acknowledging to prevent retry loop",
				zap.String("message_id", message.ID),
				zap.Error(err),
			)

			data, _ := message.Values["data"].(string)
			if dlErr := redisx.PublishDeadLetter(ctx, c.redis, shared.StreamKBGenerationQueue, GroupKBEngine, message.ID, data, err); dlErr != nil {
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
		return nil
	}

	// Cooldown to avoid immediately hitting the 30K input tokens/min rate limit.
	c.logger.Debug("Post-generation cooldown", zap.Duration("duration", PostGenerationCooldown))
	select {
	case <-ctx.Done():
	case <-time.After(PostGenerationCooldown):
	}

	return nil
}

// handleMessage processes a single KB generation job message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return &permanentError{err: fmt.Errorf("message data is not a string")}
	}

	// Parse KB generation job
	var job shared.KBGenerationJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return &permanentError{err: fmt.Errorf("failed to unmarshal KB generation job: %w", err)}
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, job.TraceContext)

	// Validate required fields
	if job.FindingType == "" {
		return &permanentError{err: fmt.Errorf("invalid KB generation job: missing finding_type")}
	}

	// Process the job
	return c.service.ProcessJob(ctx, job)
}
