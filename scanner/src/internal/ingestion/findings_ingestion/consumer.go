package findings_ingestion

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

// Consumer consumes security findings from Redis and persists them to MongoDB
type Consumer struct {
	redis    *redis.Client
	service  *Service
	logger   *zap.Logger
	activity *shared.ScanActivityTracker
}

// NewConsumer creates a new findings ingestion consumer
func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger, activity *shared.ScanActivityTracker, orgGuard *shared.OrgGuard) *Consumer {
	service := NewService(db, redisClient, logger, orgGuard)
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

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamSecurityFindings,
		Group:          GroupFindingsIngestion,
		ConsumerPrefix: "findings-worker",
		BatchSize:      shared.IngestionBatchSize,
		Handler:        c.handleMessage,
		Logger:         c.logger,
	})
}

// handleMessage processes a single security finding message
func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract data from message
	data, ok := message.Values["data"].(string)
	if !ok {
		return redisx.Permanent(fmt.Errorf("message data is not a string"))
	}

	// Parse security finding
	var finding shared.SecurityFinding
	if err := json.Unmarshal([]byte(data), &finding); err != nil {
		return redisx.Permanent(fmt.Errorf("failed to unmarshal finding: %w", err))
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	if finding.Coverage != nil {
		// Evidence about a target, not a finding: the scan monitor resolves on it.
		if finding.OrgID == "" {
			return redisx.Permanent(fmt.Errorf("coverage without org_id"))
		}
		return c.service.RecordCoverage(ctx, finding)
	}

	// Validate source field
	if finding.Source == "" {
		return redisx.Permanent(fmt.Errorf("missing required field: source"))
	}

	// Validate org_id
	if finding.OrgID == "" {
		return redisx.Permanent(fmt.Errorf("missing required field: org_id"))
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
