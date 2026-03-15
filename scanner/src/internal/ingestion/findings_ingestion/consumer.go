package findings_ingestion

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

// Consumer consumes security findings from Redis and persists them to MongoDB
type Consumer struct {
	redis    *redis.Client
	service  *Service
	logger   *zap.Logger
	activity *shared.ScanActivityTracker
}

// NewConsumer creates a new findings ingestion consumer
func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger, activity *shared.ScanActivityTracker) *Consumer {
	service := NewService(db, redisClient, logger)
	return &Consumer{
		redis:    redisClient,
		service:  service,
		logger:   logger,
		activity: activity,
	}
}

// Start begins consuming messages from the security_findings stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting findings ingestion consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamSecurityFindings, GroupFindingsIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}
	redisx.CleanupStaleConsumers(ctx, c.redis, shared.StreamSecurityFindings, GroupFindingsIngestion, c.logger)

	// Generate unique consumer name for this worker
	consumerName := "findings-worker-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("group", GroupFindingsIngestion),
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamSecurityFindings),
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
			c.logger.Info("Context cancelled, shutting down consumer")
			return ctx.Err()
		default:
			// Read messages from stream (using "0" to get pending + new messages)
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupFindingsIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamSecurityFindings, ">"},
				Count:    shared.IngestionBatchSize,
				Block:    redisReadBlockTimeout,
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

							data, _ := message.Values["data"].(string)
							if dlErr := redisx.PublishDeadLetter(ctx, c.redis, shared.StreamSecurityFindings, GroupFindingsIngestion, message.ID, data, err); dlErr != nil {
								c.logger.Warn("Failed to publish to dead-letter stream",
									zap.String("message_id", message.ID),
									zap.Error(dlErr),
								)
							}

							_ = c.redis.XAck(ctx, shared.StreamSecurityFindings, GroupFindingsIngestion, message.ID).Err()
						} else {
							c.logger.Error("Failed to process message, leaving unacknowledged for retry",
								zap.String("message_id", message.ID),
								zap.Error(err),
							)
						}
						continue
					}

					// Only acknowledge on success
					if err := c.redis.XAck(ctx, shared.StreamSecurityFindings, GroupFindingsIngestion, message.ID).Err(); err != nil {
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

// handleMessage processes a single security finding message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return &permanentError{err: fmt.Errorf("message data is not a string")}
	}

	// Parse security finding
	var finding shared.SecurityFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return &permanentError{err: fmt.Errorf("failed to unmarshal finding: %w", err)}
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	// Validate source field
	if finding.Source == "" {
		return &permanentError{err: fmt.Errorf("missing required field: source")}
	}

	// Validate org_id
	if finding.OrgID == "" {
		return &permanentError{err: fmt.Errorf("missing required field: org_id")}
	}

	// Process the finding
	if err := c.service.ProcessFinding(ctx, finding); err != nil {
		return err
	}

	// Signal scan activity for idle detection (throttled internally)
	if finding.ScanID != nil {
		c.activity.TouchActivity(ctx, *finding.ScanID)
	}

	return nil
}
