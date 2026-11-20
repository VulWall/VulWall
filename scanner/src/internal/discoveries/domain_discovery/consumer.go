package domain_discovery

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

func NewConsumer(redisClient *redis.Client, logger *zap.Logger) (*Consumer, error) {
	service, err := NewService(redisClient, logger)
	if err != nil {
		return nil, err
	}
	return &Consumer{
		redis:   redisClient,
		service: service,
		logger:  logger,
	}, nil
}

// Start begins consuming jobs from the Redis stream
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting subfinder discovery consumer")

	return redisx.ConsumeStream(ctx, c.redis, redisx.ConsumerConfig{
		Stream:         shared.StreamDomainDiscoveryQueue,
		Group:          GroupDomainDiscovery,
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

	var job shared.DiscoveryJob
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

	c.logger.Info("Processing discovery job with subfinder",
		zap.String("trace_id", job.TraceID),
		zap.String("org_id", job.OrgID),
		zap.String("host", job.Host),
	)

	// Process the job
	if err := c.service.ProcessJob(ctx, job); err != nil {
		if ctx.Err() != nil {
			return err // shutdown: ConsumeStream logs it at Info and leaves the job unACKed
		}
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
