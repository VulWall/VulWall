package audit_ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Consumer consumes system audit events from Redis and persists them to MongoDB
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new audit ingestion consumer
func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	service := NewService(db, logger)
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}
}

// Start begins consuming messages from the system_audit_logs stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting audit ingestion consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamSystemAuditLogs, GroupAuditIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	// Generate unique consumer name for this worker
	consumerName := "audit-worker-" + uuid.New().String()

	c.logger.Info("Consumer group created",
		zap.String("group", GroupAuditIngestion),
		zap.String("consumer", consumerName),
		zap.String("stream", shared.StreamSystemAuditLogs),
	)

	// Start processing messages
	return c.processMessages(ctx, consumerName)
}

// processMessages is the main message processing loop
func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Context cancelled, shutting down audit consumer")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupAuditIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamSystemAuditLogs, ">"},
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
					c.redis.XAck(ctx, shared.StreamSystemAuditLogs, GroupAuditIngestion, message.ID)
				}
			}
		}
	}
}

// handleMessage processes a single audit event message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse audit event
	var event shared.SystemAuditEvent
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		return fmt.Errorf("failed to unmarshal audit event: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, event.TraceContext)

	// Process the event
	return c.service.ProcessAuditEvent(ctx, event)
}
