package shared

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// AssetGuard answers "may ingestion still record this asset on discoveries?": the asset
// exists in the org and no delete has started on it (assets.deleting). The web app deletes an
// asset by pulling its id from asset_ids and then deleting the discoveries left with none. A
// message of that asset's scan that is still in flight (a scan closed by safety_timeout, a
// stuck consumer) would otherwise create a discovery that holds only the deleted id: hidden
// for good, and never cleaned by that delete.
//
// It caches like OrgGuard (OrgPositiveCacheTTL, OrgCacheTTL). A long negative cache is safe:
// a deleted asset never comes back (adding it again creates a new id), and the web app never
// clears deleting. The positive cache and the gap between this check and the write leave a
// short window; the web delete also pulls the ids of assets that no longer exist, so the next
// delete cleans what slips through.
//
// Thread-safe: multiple ingestion workers may call Exists concurrently.
type AssetGuard struct {
	// lookup performs the underlying check; a field so the cache can be tested without a
	// database. NewAssetGuard wires it to a MongoDB FindOne.
	lookup func(ctx context.Context, orgID, assetID string) bool

	mu    sync.Mutex
	cache map[assetKey]orgCacheEntry
}

type assetKey struct{ orgID, assetID string }

// NewAssetGuard creates an AssetGuard backed by the assets collection in db.
func NewAssetGuard(db *mongo.Database, logger *zap.Logger) *AssetGuard {
	return &AssetGuard{
		cache: make(map[assetKey]orgCacheEntry),
		lookup: func(ctx context.Context, orgID, assetID string) bool {
			filter := ObjectIDFilter(assetID)
			filter["org_id"] = orgID
			filter["deleting"] = bson.M{"$ne": true}
			err := db.Collection(CollectionAssets).FindOne(ctx, filter).Err()
			if err != nil && err != mongo.ErrNoDocuments {
				// Fail open, as OrgGuard does: a DB blip must not drop real results. The
				// web delete cleans an id that gets through this way.
				logger.Warn("Asset existence check failed, treating asset as present",
					zap.String("org_id", orgID),
					zap.String("asset_id", assetID),
					zap.Error(err),
				)
			}
			return err != mongo.ErrNoDocuments
		},
	}
}

// Exists reports whether assetID is an asset of orgID that is not being deleted. An empty
// orgID or assetID is always false.
func (g *AssetGuard) Exists(ctx context.Context, orgID, assetID string) bool {
	if orgID == "" || assetID == "" {
		return false
	}
	key := assetKey{orgID, assetID}
	now := time.Now()

	g.mu.Lock()
	if entry, ok := g.cache[key]; ok && now.Sub(entry.checkedAt) < entry.ttl() {
		g.mu.Unlock()
		return entry.exists
	}
	g.mu.Unlock()

	exists := g.lookup(ctx, orgID, assetID)

	g.mu.Lock()
	g.cache[key] = orgCacheEntry{exists: exists, checkedAt: now}
	g.mu.Unlock()

	return exists
}
