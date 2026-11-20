package redisx

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
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

// PublishDeadLetter sends a permanently failed message to the dead-letter stream.
// This preserves the original message data alongside error context for debugging and replay.
func PublishDeadLetter(ctx context.Context, client *redis.Client, sourceStream, consumerGroup, messageID, data string, err error) error {
	_, xaddErr := client.XAdd(ctx, &redis.XAddArgs{
		Stream: shared.StreamDeadLetter,
		Values: map[string]interface{}{
			"source_stream":  sourceStream,
			"consumer_group": consumerGroup,
			"message_id":     messageID,
			"data":           data,
			"error":          err.Error(),
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		},
	}).Result()
	if xaddErr != nil {
		return fmt.Errorf("failed to publish to dead-letter stream: %w", xaddErr)
	}
	return nil
}

// TryAcquireLock attempts a distributed lock via SET NX with TTL.
// Returns true if acquired. ttl is a crash safety net — pick ttl > the
// guarded operation's max duration so ReleaseLock never frees a lock we no longer own.
func TryAcquireLock(ctx context.Context, client *redis.Client, key, value string, ttl time.Duration) (bool, error) {
	return client.SetNX(ctx, key, value, ttl).Result()
}

// releaseLockScript deletes the key only if its value still matches the caller's,
// so a replica can never free a lock another replica now owns (TTL-expiry race).
var releaseLockScript = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
end
return 0`)

// ReleaseLock frees a lock acquired with TryAcquireLock, but only if value still
// matches (ownership check). Best-effort. Uses a fresh short context so a cancelled
// parent (graceful shutdown) doesn't skip release and leave the lock held until TTL.
func ReleaseLock(ctx context.Context, client *redis.Client, key, value string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_ = releaseLockScript.Run(ctx, client, []string{key}, value).Err()
}
