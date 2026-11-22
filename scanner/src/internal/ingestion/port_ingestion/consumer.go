package port_ingestion

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

type Consumer struct {
	redis    *redis.Client
	service  *Service
	logger   *zap.Logger
	activity *shared.ScanActivityTracker
}

func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger, activity *shared.ScanActivityTracker, orgGuard *shared.OrgGuard, assetGuard *shared.AssetGuard) *Consumer {
	return &Consumer{
		redis:    redisClient,
		service:  NewService(db, redisClient, logger, orgGuard, assetGuard),
		logger:   logger,
		activity: activity,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	// Create consumer group if it doesn't exist
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupPortIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	c.logger.Info("Starting port ingestion consumer",
		zap.String("stream", shared.StreamIPDiscoveryResults),
		zap.String("group", GroupPortIngestion),
	)

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamIPDiscoveryResults,
		Group:          GroupPortIngestion,
		ConsumerPrefix: "port-ingestion",
		BatchSize:      shared.IngestionBatchSize,
		Handler:        c.handleMessage,
		Logger:         c.logger,
	})
}

func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract finding data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message missing 'data' field"))
	}

	var finding shared.IPDiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal finding: %w", err))
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	c.logger.Info("Processing port discovery finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Source),
		zap.String("ip", finding.IP),
		zap.Int("port", finding.Port),
	)

	// Process the finding
	if err := c.service.ProcessFinding(ctx, finding); err != nil {
		return fmt.Errorf("failed to process finding: %w", err)
	}

	// Signal scan activity for idle detection (throttled internally)
	if finding.ScanID != nil {
		c.activity.TouchActivity(ctx, *finding.ScanID)
	}

	c.logger.Info("Successfully processed port finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
	)

	return nil
}
