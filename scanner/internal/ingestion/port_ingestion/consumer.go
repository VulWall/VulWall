package port_ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/telemetry"
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
		service: NewService(db, redisClient, logger),
		logger:  logger,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	// Create consumer group if it doesn't exist
	err := c.redis.XGroupCreateMkStream(ctx, shared.StreamIPDiscoveryResults, GroupPortIngestion, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return fmt.Errorf("failed to create consumer group: %w", err)
	}

	c.logger.Info("Starting port ingestion consumer",
		zap.String("stream", shared.StreamIPDiscoveryResults),
		zap.String("group", GroupPortIngestion),
	)

	// Start message processing
	return c.processMessages(ctx, uuid.New().String())
}

func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Port ingestion consumer context cancelled, shutting down")
			return ctx.Err()
		default:
			// Read messages from stream (using "0" to get pending + new messages)
			streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    GroupPortIngestion,
				Consumer: consumerName,
				Streams:  []string{shared.StreamIPDiscoveryResults, ">"},
				Count:    shared.IngestionBatchSize,
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
					if err := c.redis.XAck(ctx, shared.StreamIPDiscoveryResults, GroupPortIngestion, message.ID).Err(); err != nil {
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

	var finding shared.IPDiscoveryFinding
	if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
		return fmt.Errorf("failed to unmarshal finding: %w", err)
	}

	// Extract trace context from message to link spans across service boundaries
	ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

	c.logger.Info("Processing port discovery finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Scanner),
		zap.String("ip", finding.IP),
		zap.Int("port", finding.Port),
	)

	// Process the finding
	if err := c.service.ProcessFinding(ctx, finding); err != nil {
		return fmt.Errorf("failed to process finding: %w", err)
	}

	c.logger.Info("Successfully processed port finding",
		zap.String("message_id", message.ID),
		zap.String("trace_id", finding.TraceID),
	)

	return nil
}
