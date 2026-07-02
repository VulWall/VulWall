package port_ingestion

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

type Consumer struct {
	redis    *redis.Client
	service  *Service
	logger   *zap.Logger
	activity *shared.ScanActivityTracker
}

func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger, activity *shared.ScanActivityTracker, orgGuard *shared.OrgGuard) *Consumer {
	return &Consumer{
		redis:    redisClient,
		service:  NewService(db, redisClient, logger, orgGuard),
		logger:   logger,
		activity: activity,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	// Create consumer group if it doesn't exist
	if err := redisx.CreateConsumerGroup(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupPortIngestion); err != nil {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}
	redisx.CleanupStaleConsumers(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupPortIngestion, c.logger)

	c.logger.Info("Starting port ingestion consumer",
		zap.String("stream", shared.StreamIPDiscoveryResults),
		zap.String("group", GroupPortIngestion),
	)

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamIPDiscoveryResults,
		Group:          GroupPortIngestion,
		ConsumerPrefix: "port-ingestion",
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
			if dlErr := redisx.PublishDeadLetter(ctx, c.redis, shared.StreamIPDiscoveryResults, GroupPortIngestion, message.ID, data, err); dlErr != nil {
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

func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract finding data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return &permanentError{err: fmt.Errorf("message missing 'data' field")}
	}

	var finding shared.IPDiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return &permanentError{err: fmt.Errorf("failed to unmarshal finding: %w", err)}
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
