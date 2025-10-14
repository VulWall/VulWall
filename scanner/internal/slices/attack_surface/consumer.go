package attack_surface

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Consumer struct {
	redis   *redis.Client
	db      *mongo.Database
	service *Service
	logger  *zap.Logger
}

func NewConsumer(redisClient *redis.Client, db *mongo.Database, shodanAPIKey string, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		db:      db,
		service: NewService(db, shodanAPIKey, logger),
		logger:  logger,
	}
}

// Start begins consuming jobs from the Redis stream
func (c *Consumer) Start(ctx context.Context) error {
	consumerName := "worker-" + uuid.New().String()
	c.logger.Info("Starting attack surface consumer", zap.String("consumer", consumerName))

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Shutting down attack surface consumer")
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
		Group:    GroupAttackSurface,
		Consumer: consumerName,
		Streams:  []string{StreamAttackSurface, ">"},
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
			if err := c.redis.XAck(ctx, StreamAttackSurface, GroupAttackSurface, message.ID).Err(); err != nil {
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

	var job AttackSurfaceJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		c.logger.Error("Failed to unmarshal job", zap.Error(err))
		return err
	}

	c.logger.Info("Processing attack surface job",
		zap.String("trace_id", job.TraceID),
		zap.String("host", job.Host),
	)

	// Process the job
	if err := c.service.ProcessJob(ctx, job); err != nil {
		c.logger.Error("Job processing failed",
			zap.String("trace_id", job.TraceID),
			zap.Error(err),
		)
		return err
	}

	c.logger.Info("Job processed successfully",
		zap.String("trace_id", job.TraceID),
	)

	return nil
}
