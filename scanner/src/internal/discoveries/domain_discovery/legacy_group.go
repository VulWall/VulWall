package domain_discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// DropLegacyGroup removes the consumer group that domain discovery used before it was
// renamed to GroupDomainDiscovery. It must run before GroupDomainDiscovery is created.
//
// When the new group does not exist yet, it is created at the old group's last-delivered id,
// so the job queue (which is never trimmed) is not read again from the start. Jobs the old
// group had read but not ACKed are dropped, as on any restart (see ReleaseOrphanedPending).
func DropLegacyGroup(ctx context.Context, rdb *redis.Client, log *zap.Logger) error {
	stream := shared.StreamDomainDiscoveryQueue
	groups, err := rdb.XInfoGroups(ctx, stream).Result()
	if err != nil {
		if strings.Contains(err.Error(), "no such key") {
			return nil
		}
		return fmt.Errorf("list groups of %s: %w", stream, err)
	}

	var legacy *redis.XInfoGroup
	hasNew := false
	for i := range groups {
		switch groups[i].Name {
		case legacyGroup:
			legacy = &groups[i]
		case GroupDomainDiscovery:
			hasNew = true
		}
	}
	if legacy == nil {
		return nil
	}

	if !hasNew {
		if err := rdb.XGroupCreate(ctx, stream, GroupDomainDiscovery, legacy.LastDeliveredID).Err(); err != nil {
			return fmt.Errorf("create %s/%s: %w", stream, GroupDomainDiscovery, err)
		}
	}
	if err := rdb.XGroupDestroy(ctx, stream, legacyGroup).Err(); err != nil {
		return fmt.Errorf("delete %s/%s: %w", stream, legacyGroup, err)
	}
	log.Info("Deleted the old domain discovery consumer group",
		zap.String("stream", stream), zap.String("group", legacyGroup),
		zap.String("replaced_by", GroupDomainDiscovery), zap.Int64("dropped_pending", legacy.Pending))
	return nil
}
