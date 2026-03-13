package domain_ingestion

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

type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		service: NewService(db, redisClient, logger),
		logger:  logger,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	// Create consumer group if it doesn't exist
	err := c.redis.XGroupCreateMkStream(ctx, shared.StreamDomainDiscoveryResults, GroupDomainIngestion, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	c.logger.Info("Starting domain ingestion consumer",
		zap.String("stream", shared.StreamDomainDiscoveryResults),
		zap.String("group", GroupDomainIngestion),
	)

	// Start message processing
	return c.processMessages(ctx, uuid.New().String())
}

// permanentError wraps errors that should not be retried (e.g., invalid message data).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Domain ingestion consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from stream (using "0" to get pending + new messages)
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupDomainIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDomainDiscoveryResults, ">"},
				Count:    shared.IngestionBatchSize,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					// No messages available, continue
					continue
				}
				c.logger.Error("Failed to read from stream", zap.Error(err))
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Second):
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
							if dlErr := redisx.PublishDeadLetter(ctx, c.redis, shared.StreamDomainDiscoveryResults, GroupDomainIngestion, message.ID, data, err); dlErr != nil {
								c.logger.Warn("Failed to publish to dead-letter stream",
									zap.String("message_id", message.ID),
									zap.Error(dlErr),
								)
							}

							_ = c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupDomainIngestion, message.ID).Err()
						} else {
							c.logger.Error("Failed to process message, leaving unacknowledged for retry",
								zap.String("message_id", message.ID),
								zap.Error(err),
							)
						}
						continue
					}

					// Acknowledge message
					if err := c.redis.XAck(ctx, shared.StreamDomainDiscoveryResults, GroupDomainIngestion, message.ID).Err(); err != nil {
						c.logger.Error("Failed to acknowledge message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}
				}
			}
		}
	}
}

func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract finding data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return &permanentError{err: fmt.Errorf("message missing 'data' field")}
	}

	var finding shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return &permanentError{err: fmt.Errorf("failed to unmarshal finding: %w", err)}
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	c.logger.Info("Processing domain discovery finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)

	// Process the finding
	if err := c.service.ProcessFinding(ctx, finding); err != nil {
		return fmt.Errorf("failed to process finding: %w", err)
	}

	c.logger.Info("Successfully processed domain finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
	)

	return nil
}
