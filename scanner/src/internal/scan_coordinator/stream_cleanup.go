package scan_coordinator

import (
	"context"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// StreamCleaner trims Redis streams that have been fully processed by all consumer groups.
// It only trims messages that ALL consumer groups have acknowledged, preventing data loss.
type StreamCleaner struct {
	redis  *redis.Client
	logger *zap.Logger
}

// NewStreamCleaner creates a new stream cleaner
func NewStreamCleaner(redisClient *redis.Client, logger *zap.Logger) *StreamCleaner {
	return &StreamCleaner{
		redis:  redisClient,
		logger: logger,
	}
}

// streamsToClean returns the list of result/finding streams that need safe cleanup.
// Trigger streams (domain_scan_triggers, port_scan_triggers) use MAXLEN and are NOT included here.
// Job queues (discovery_queue, etc.) use maxLen=0 and are managed by consumers.
func streamsToClean() []string {
	return []string{
		shared.StreamDomainDiscoveryResults,
		shared.StreamIPDiscoveryResults,
		shared.StreamSecurityFindings,
		shared.StreamDiscoveryEnrichmentResults,
		shared.StreamKBGenerationResults,
	}
}

// Run executes a single cleanup pass across all monitored streams.
// Designed to be called by cron scheduler.
func (sc *StreamCleaner) Run() {
	ctx := context.Background()
	totalTrimmed := int64(0)

	for _, stream := range streamsToClean() {
		trimmed, err := sc.cleanStream(ctx, stream)
		if err != nil {
			sc.logger.Error("Failed to clean stream",
				zap.String("stream", stream),
				zap.Error(err),
			)
			continue
		}
		totalTrimmed += trimmed
	}

	if totalTrimmed > 0 {
		sc.logger.Info("Stream cleanup completed",
			zap.Int64("total_trimmed", totalTrimmed),
		)
	}
}

// cleanStream trims a single stream up to the safe point where all consumer groups have processed.
func (sc *StreamCleaner) cleanStream(ctx context.Context, stream string) (int64, error) {
	groups, err := sc.redis.XInfoGroups(ctx, stream).Result()
	if err != nil {
		if err.Error() == "ERR no such key" {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get consumer groups: %w", err)
	}

	if len(groups) == 0 {
		return 0, nil
	}

	// Find the safe trim point: the minimum across all groups
	safeTrimID := ""

	for _, group := range groups {
		groupSafeID, err := sc.getGroupSafeID(ctx, stream, group)
		if err != nil {
			sc.logger.Warn("Failed to get safe ID for group, skipping stream cleanup",
				zap.String("stream", stream),
				zap.String("group", group.Name),
				zap.Error(err),
			)
			return 0, nil // Skip entire stream if any group fails — safety first
		}

		if groupSafeID == "" {
			return 0, nil
		}

		if safeTrimID == "" || groupSafeID < safeTrimID {
			safeTrimID = groupSafeID
		}
	}

	if safeTrimID == "" {
		return 0, nil
	}

	trimmed, err := sc.redis.XTrimMinID(ctx, stream, safeTrimID).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to trim stream: %w", err)
	}

	if trimmed > 0 {
		sc.logger.Info("Trimmed stream",
			zap.String("stream", stream),
			zap.Int64("messages_trimmed", trimmed),
			zap.String("trim_point", safeTrimID),
		)
	}

	return trimmed, nil
}

// getGroupSafeID returns the oldest message ID that this group still needs.
// If there are pending messages, returns the oldest pending ID.
// Otherwise, returns the last-delivered-id (everything up to that point is safe).
func (sc *StreamCleaner) getGroupSafeID(ctx context.Context, stream string, group redis.XInfoGroup) (string, error) {
	if group.Pending > 0 {
		pending, err := sc.redis.XPending(ctx, stream, group.Name).Result()
		if err != nil {
			return "", fmt.Errorf("failed to get pending summary: %w", err)
		}

		if pending.Count > 0 {
			return pending.Lower, nil
		}
	}

	return group.LastDeliveredID, nil
}
