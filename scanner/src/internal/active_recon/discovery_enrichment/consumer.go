package discovery_enrichment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Consumer consumes enrichment jobs from discovery_enrichment_queue
type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

// NewConsumer creates a new discovery enrichment consumer
func NewConsumer(redisClient *redis.Client, logger *zap.Logger) (*Consumer, error) {
	service, err := NewService(redisClient, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}, nil
}

// Start begins consuming enrichment jobs from the queue
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting discovery enrichment consumer (single queue)")

	// Create consumer group
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamDiscoveryEnrichmentQueue, GroupDiscoveryEnrichment); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamDiscoveryEnrichmentQueue,
		Group:          GroupDiscoveryEnrichment,
		ConsumerPrefix: "discovery-enrichment",
		BatchSize:      ConsumerBatchSize,
		Handler:        c.handleEnrichmentJob,
		Logger:         c.logger,
	})
}

// handleEnrichmentJob processes a single enrichment job message
func (c *Consumer) handleEnrichmentJob(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message data is not a string"))
	}

	// Parse enrichment job
	var job shared.EnrichmentJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal enrichment job: %w", err))
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, job.TraceContext)

	// Validate org_id
	if job.OrgID == "" {
		c.logger.Warn("Skipping job without org_id",
			zap.String("message_id", message.ID),
		)
		return nil
	}

	// Validate asset_type
	if job.AssetType == "" {
		c.logger.Warn("Skipping job without asset_type",
			zap.String("message_id", message.ID),
			zap.String("discovery_id", job.DiscoveryID),
		)
		return nil
	}

	// Process enrichment
	return c.service.ProcessEnrichment(ctx, job)
}
