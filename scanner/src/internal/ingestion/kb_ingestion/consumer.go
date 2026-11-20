package kb_ingestion

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
		Handler:        c.handleMessage,
		Logger:         c.logger,
	})
}

// handleMessage processes a single KB generation result message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message data is not a string"))
	}

	// Parse KB generation result
	var result shared.KBGenerationResult
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal KB result: %w", err))
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, result.TraceContext)

	// Process the result
	return c.service.ProcessEntry(ctx, result)
}
