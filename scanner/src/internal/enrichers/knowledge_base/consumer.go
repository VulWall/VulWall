package knowledge_base

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

	// Generate unique consumer name for this worker
	consumerName := "kb-engine-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("group", GroupKBEngine),
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamKBGenerationQueue),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

const redisReadBlockTimeout = 5 * time.Second

// permanentError wraps errors that should not be retried (e.g., invalid message data).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// processMessages is the main message processing loop
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Context cancelled, shutting down KB engine consumer")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupKBEngine,
				Consumer: consumerName,
				Streams:  []string{shared.StreamKBGenerationQueue, ">"},
				Count:    int64(ConsumerBatchSize),
				Block:    redisReadBlockTimeout,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				c.logger.Error("Failed to read from stream", zap.Error(err))
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(redisReadBlockTimeout):
				}
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

							// Preserve original message data in the dead-letter stream for debugging
							data, _ := message.Values["data"].(string)
							if dlErr := redisx.PublishDeadLetter(ctx, c.redis, shared.StreamKBGenerationQueue, GroupKBEngine, message.ID, data, err); dlErr != nil {
								c.logger.Warn("Failed to publish to dead-letter stream",
									zap.String("message_id", message.ID),
									zap.Error(dlErr),
								)
							}

							_ = c.redis.XAck(ctx, shared.StreamKBGenerationQueue, GroupKBEngine, message.ID).Err()
						} else {
							c.logger.Error("Failed to process message, leaving unacknowledged for retry",
								zap.String("message_id", message.ID),
								zap.Error(err),
							)
						}
						continue
					}

					// Only acknowledge on success
					if err := c.redis.XAck(ctx, shared.StreamKBGenerationQueue, GroupKBEngine, message.ID).Err(); err != nil {
						c.logger.Warn("Failed to acknowledge message — will be redelivered",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}

					// Cooldown to avoid immediately hitting the 30K input tokens/min rate limit.
					c.logger.Debug("Post-generation cooldown", zap.Duration("duration", PostGenerationCooldown))
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(PostGenerationCooldown):
					}
				}
			}
		}
	}
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
