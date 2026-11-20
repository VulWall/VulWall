package port_discovery

import (
	"context"
	"encoding/json"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

func NewConsumer(redisClient *redis.Client, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		service: NewService(redisClient, logger),
		logger:  logger,
	}
}

// Start begins consuming jobs from the Redis stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting port discovery consumer")

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamIPDiscoveryQueue,
		Group:          GroupPortDiscovery,
		ConsumerPrefix: "worker",
		BatchSize:      ConsumerBatchSize,
		Handler:        c.processMessage,
		Logger:         c.logger,
	})
}

func (c *Consumer) processMessage(ctx context.Context, message redis.XMessage) error {
	// Parse the job from the message
	data, ok := message.Values["data"].(string)
	if !ok {
		c.logger.Warn("Message missing data field", zap.String("message_id", message.ID))
		return nil
	}

	var job shared.IPDiscoveryJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		c.logger.Error("Failed to unmarshal job", zap.Error(err))
		return redisx.Permanent(err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, job.TraceContext)

	// Validate org_id is present (required)
	if job.OrgID == "" {
		c.logger.Warn("Skipping job: missing org_id",
			zap.String("message_id", message.ID),
			zap.String("trace_id", job.TraceID),
		)
		return nil
	}

	c.logger.Info("Processing IP discovery job",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("ip", job.IP),
	)

	// Process the job
	if err := c.service.ProcessJob(ctx, job); err != nil {
		c.logger.Error("Job processing failed",
			zap.String("trace_id", job.TraceID),
			zap.String("org_id", job.OrgID),
			zap.Error(err),
		)
		return err
	}

	c.logger.Info("Job processed successfully",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
	)

	return nil
}
