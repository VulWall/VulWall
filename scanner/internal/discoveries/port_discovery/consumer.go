package port_discovery

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

func NewConsumer(redisClient *redis.Client, ipEnrichmentDBPath string, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		service: NewService(redisClient, ipEnrichmentDBPath, logger),
		logger:  logger,
	}
}

// Start begins consuming jobs from the Redis stream
func (c *Consumer) Start(ctx context.Context) error {
	consumerName := "worker-" + uuid.New().String()
	c.logger.Info("Starting port discovery consumer", zap.String("consumer", consumerName))

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Shutting down port discovery consumer")
			return ctx.Err()
		default:
			if err := c.processMessages(ctx, consumerName); err != nil {
				c.logger.Error("Error processing messages", zap.Error(err))
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    GroupPortDiscovery,
		Consumer: consumerName,
		Streams:  []string{shared.StreamIPDiscoveryQueue, ">"},
		Count:    1,
		Block:    5 * time.Second,
	}).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// No messages available
			return nil
		}
		return err
	}

	for _, stream := range streams {
		for _, message := range stream.Messages {
			if err := c.processMessage(ctx, message); err != nil {
				c.logger.Error("Failed to process message",
					zap.String("message_id", message.ID),
					zap.Error(err),
				)
				continue
			}

			// Acknowledge the message
			if err := c.redis.XAck(ctx, shared.StreamIPDiscoveryQueue, GroupPortDiscovery, message.ID).Err(); err != nil {
				c.logger.Error("Failed to acknowledge message",
					zap.String("message_id", message.ID),
					zap.Error(err),
				)
			}
		}
	}

	return nil
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
		return err
	}

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
