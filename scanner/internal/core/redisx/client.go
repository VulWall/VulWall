package redisx

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/config"
)

func NewClient(cfg *config.Config) (*redis.Client, error) {
	// Parse Redis URL
	opts, err := redis.ParseURL(cfg.RedisURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return client, nil
}

// CreateConsumerGroup creates a consumer group for a stream if it doesn't exist.
// Starts reading from the beginning ("0") — use for job queues where every message must be processed.
func CreateConsumerGroup(ctx context.Context, client *redis.Client, stream, group string) error {
	err := client.XGroupCreateMkStream(ctx, stream, group, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	return nil
}

// CreateConsumerGroupFromLatest creates a consumer group that starts from the latest message ("$").
// Use for trigger/notification streams where skipping old messages is acceptable.
// If the group already exists, this is a no-op (does NOT change the existing group's position).
func CreateConsumerGroupFromLatest(ctx context.Context, client *redis.Client, stream, group string) error {
	err := client.XGroupCreateMkStream(ctx, stream, group, "$").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return err
	}
	return nil
}

// PublishToStream publishes a message to a Redis stream
// The message will be marshaled to JSON and published with a "data" field
// This is a generic helper to reduce code duplication across services
// If maxLen > 0, the stream will be trimmed to approximately that size (using ~ for better performance)
func PublishToStream(ctx context.Context, client *redis.Client, stream string, message interface{}, maxLen int64) error {
	// Marshal message to JSON
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Publish to stream with optional MAXLEN trimming
	args := &redis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}

	// Apply MAXLEN if specified (using approximate ~ for better performance)
	if maxLen > 0 {
		args.MaxLen = maxLen
		args.Approx = true
	}

	_, err = client.XAdd(ctx, args).Result()

	if err != nil {
		return fmt.Errorf("failed to publish to stream %s: %w", stream, err)
	}

	return nil
}
