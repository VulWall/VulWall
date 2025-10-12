package passive_recon

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Consumer struct {
	redis   *redis.Client
	db      *mongo.Database
	service *Service
	logger  *zap.Logger
}

func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		db:      db,
		service: NewService(logger),
		logger:  logger,
	}
}

// Start begins consuming jobs from the Redis stream
func (c *Consumer) Start(ctx context.Context) error {
	consumerName := "worker-" + uuid.New().String()
	c.logger.Info("Starting passive recon consumer", zap.String("consumer", consumerName))

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Shutting down passive recon consumer")
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
		Group:    GroupPassiveRecon,
		Consumer: consumerName,
		Streams:  []string{StreamPassiveRecon, ">"},
		Count:    1,
		Block:    5 * time.Second,
	}).Result()

	if err != nil {
		if err == redis.Nil {
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
			if err := c.redis.XAck(ctx, StreamPassiveRecon, GroupPassiveRecon, message.ID).Err(); err != nil {
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
		return nil
	}

	var job shared.ScanJob
	if err := json.Unmarshal([]byte(data), &job); err != nil {
		c.logger.Error("Failed to unmarshal job", zap.Error(err))
		return err
	}

	c.logger.Info("Processing scan job",
		zap.String("scan_id", job.ScanID),
		zap.String("domain", job.Domain),
	)

	// Process the scan
	result, err := c.service.ProcessScan(ctx, job)
	if err != nil {
		c.logger.Error("Scan processing failed",
			zap.String("scan_id", job.ScanID),
			zap.Error(err),
		)
	}

	// Save result to MongoDB
	collection := c.db.Collection(shared.CollectionScanResults)
	if _, err := collection.InsertOne(ctx, result); err != nil {
		c.logger.Error("Failed to save scan result",
			zap.String("scan_id", job.ScanID),
			zap.Error(err),
		)
		return err
	}

	c.logger.Info("Scan result saved",
		zap.String("scan_id", job.ScanID),
		zap.String("status", result.Status),
	)

	return nil
}
