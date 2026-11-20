package audit_ingestion

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
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

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamSystemAuditLogs,
		Group:          GroupAuditIngestion,
		ConsumerPrefix: "audit-worker",
		BatchSize:      shared.IngestionBatchSize,
		Handler:        c.handleMessage,
		Logger:         c.logger,
	})
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
