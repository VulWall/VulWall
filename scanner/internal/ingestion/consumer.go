package ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Consumer struct {
	redis   *redis.Client
	service *Service
	logger  *zap.Logger
}

func NewConsumer(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Consumer {
	return &Consumer{
		redis:   redisClient,
		service: NewService(db, logger),
		logger:  logger,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	// Create consumer group if it doesn't exist
	err := c.redis.XGroupCreateMkStream(ctx, shared.StreamDiscoveries, GroupIngestion, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	c.logger.Info("Starting ingestion consumer",
		zap.String("stream", shared.StreamDiscoveries),
		zap.String("group", GroupIngestion),
	)

	// Start message processing
	return c.processMessages(ctx, uuid.New().String())
}

func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from stream
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamDiscoveries, ">"},
				Count:    1,
				Block:    5 * time.Second,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					// No messages available, continue
					continue
				}
				c.logger.Error("Failed to read from stream", zap.Error(err))
				time.Sleep(2 * time.Second)
				continue
			}

			// Process each message
			for _, stream := range streams {
				for _, message := range stream.Messages {
					if err := c.handleMessage(ctx, message); err != nil {
						c.logger.Error("Failed to handle message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
						continue
					}

					// Acknowledge message
					if err := c.redis.XAck(ctx, shared.StreamDiscoveries, GroupIngestion, message.ID).Err(); err != nil {
						c.logger.Error("Failed to acknowledge message",
							zap.String("message_id", message.ID),
							zap.Error(err),
						)
					}
				}
			}
		}
	}
}

func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
	// Extract finding data from message
	dataStr, ok := message.Values["data"].(string)
	if !ok {
		return fmt.Errorf("message missing 'data' field")
	}

	var finding DiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal finding: %w", err)
	}

	c.logger.Info("Processing discovery finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)

	// Process the finding
	if err := c.service.ProcessFinding(ctx, finding); err != nil {
		return fmt.Errorf("failed to process finding: %w", err)
	}

	c.logger.Info("Successfully processed finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
	)

	return nil
}
