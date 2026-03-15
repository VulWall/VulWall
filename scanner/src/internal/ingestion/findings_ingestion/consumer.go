package findings_ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamSecurityFindings,
		Group:          GroupFindingsIngestion,
		ConsumerPrefix: "findings-worker",
		BatchSize:      shared.IngestionBatchSize,
		Handler:        c.handleMessageWithDeadLetter,
		Logger:         c.logger,
	})
}

// permanentError wraps errors that should not be retried (e.g., invalid message data).
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// handleMessageWithDeadLetter wraps handleMessage with dead-letter logic.
// Permanent errors are sent to the dead-letter stream. All errors are logged
// but nil is returned so ConsumeStream handles the ACK.
func (c *Consumer) handleMessageWithDeadLetter(ctx context.Context, message redis.XMessage) error {
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
			return nil
		}

		c.logger.Error("Failed to process message",
			zap.String("message_id", message.ID),
			zap.Error(err),
		)
	}

	return nil
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
