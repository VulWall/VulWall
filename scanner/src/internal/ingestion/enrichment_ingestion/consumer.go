package enrichment_ingestion

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

// Consumer consumes enrichment findings from Redis stream
type Consumer struct {
	redis    *redis.Client
	service  *Service
	logger   *zap.Logger
	activity *shared.ScanActivityTracker
}

// NewConsumer creates a new enrichment ingestion consumer
func NewConsumer(redis *redis.Client, db *mongo.Database, logger *zap.Logger, activity *shared.ScanActivityTracker) *Consumer {
	service := NewService(db, redis, logger)
	return &Consumer{
		redis:    redis,
		service:  service,
		logger:   logger,
		activity: activity,
	}
}

// Start begins consuming messages from asset_enrichment_results stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting enrichment ingestion consumer")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDiscoveryEnrichmentResults, GroupEnrichmentIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamDiscoveryEnrichmentResults,
		Group:          GroupEnrichmentIngestion,
		ConsumerPrefix: "enrichment-ingestion",
		BatchSize:      shared.IngestionBatchSize,
		Handler:        c.handleMessage,
		Logger:         c.logger,
	})
}

// handleMessage processes a single enrichment message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message data is not a string")
	}

	// Parse enrichment finding
	var enrichment shared.EnrichmentFinding
	if err := json.Unmarshal([]byte(data), &enrichment); err != nil {
		return fmt.Errorf("failed to unmarshal enrichment: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, enrichment.TraceContext)

	// Validate org_id
	if enrichment.OrgID == "" {
		c.logger.Warn("Skipping enrichment without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Process the enrichment
	if err := c.service.ProcessEnrichment(ctx, enrichment); err != nil {
		return err
	}

	// Signal scan activity for idle detection (throttled internally)
	if enrichment.ScanID != nil {
		c.activity.TouchActivity(ctx, *enrichment.ScanID)
	}

	return nil
}
