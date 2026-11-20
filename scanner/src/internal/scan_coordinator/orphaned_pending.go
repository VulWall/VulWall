package scan_coordinator

import (
	"context"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// consumerAdmin lists and deletes the consumers of one stream consumer group.
type consumerAdmin interface {
	consumers(ctx context.Context, stream, group string) ([]redis.XInfoConsumer, error)
	deleteConsumer(ctx context.Context, stream, group, name string) error
}

type redisConsumerAdmin struct{ rdb *redis.Client }

func (a redisConsumerAdmin) consumers(ctx context.Context, stream, group string) ([]redis.XInfoConsumer, error) {
	return a.rdb.XInfoConsumers(ctx, stream, group).Result()
}

func (a redisConsumerAdmin) deleteConsumer(ctx context.Context, stream, group, name string) error {
	return a.rdb.XGroupDelConsumer(ctx, stream, group, name).Err()
}

// ReleaseOrphanedPending removes every consumer that a previous scanner process left in the
// scan-pipeline groups, together with its pending entries. It must run at startup, after
// CloseInterruptedScans and before any consumer starts.
//
// Every process gives its consumers new names and reads only new messages (">"), so entries
// that a previous process read but never ACKed are never delivered again. The scan they
// belonged to was just closed as interrupted, but the entries would keep the pipeline from
// ever looking quiescent: every later scan would then wait for the 15-minute idle timeout,
// and could be closed (and resolve findings) while a slow scanner was still working.
//
// Like CloseInterruptedScans, this assumes one scanner process per Redis.
func ReleaseOrphanedPending(ctx context.Context, rdb *redis.Client, log *zap.Logger) error {
	return releaseOrphanedPending(ctx, redisConsumerAdmin{rdb}, scanPipelineGroups(), log)
}

func releaseOrphanedPending(ctx context.Context, admin consumerAdmin, groups []StreamGroup, log *zap.Logger) error {
	for _, g := range groups {
		consumers, err := admin.consumers(ctx, g.Stream, g.Group)
		if err != nil {
			if isMissingStreamOrGroup(err) {
				continue
			}
			return fmt.Errorf("list consumers of %s/%s: %w", g.Stream, g.Group, err)
		}
		for _, c := range consumers {
			if err := admin.deleteConsumer(ctx, g.Stream, g.Group, c.Name); err != nil {
				return fmt.Errorf("delete consumer %s of %s/%s: %w", c.Name, g.Stream, g.Group, err)
			}
			if c.Pending > 0 {
				log.Warn("Dropped work left unfinished by a previous scanner process",
					zap.String("stream", g.Stream), zap.String("group", g.Group),
					zap.String("consumer", c.Name), zap.Int64("pending", c.Pending))
			}
		}
	}
	return nil
}

// isMissingStreamOrGroup reports a stream or group that does not exist yet (fresh install).
func isMissingStreamOrGroup(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "NOGROUP") || strings.Contains(msg, "no such key")
}
