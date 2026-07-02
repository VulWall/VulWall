package shared

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// OrgCacheTTL controls how long an org-existence result is cached before it is
// re-checked against MongoDB. Both positive and negative results are cached;
// the negative cache matters most, since a deleted org whose scan is still in
// flight would otherwise trigger a MongoDB lookup for every orphan result.
const OrgCacheTTL = 5 * time.Minute

// orgCacheEntry is a single cached org-existence result.
type orgCacheEntry struct {
	exists    bool
	checkedAt time.Time
}

// OrgGuard answers "does this organization still exist?" with an in-memory,
// TTL-bounded cache in front of MongoDB. It exists because an org can be
// deleted (Admin/Dashboard cascade delete) while its scan pipeline is still in
// flight or while results sit in Redis result streams. Ingestion write paths
// consult the guard and soft-skip results for orgs that no longer exist,
// preventing orphan documents from being recreated after a delete.
//
// Thread-safe: multiple ingestion workers may call Exists concurrently.
type OrgGuard struct {
	logger *zap.Logger

	// lookup performs the underlying existence check. It is a field (not a
	// hard-coded MongoDB call) so the cache logic can be unit-tested without a
	// database. NewOrgGuard wires it to a MongoDB FindOne.
	lookup func(ctx context.Context, orgID string) bool

	mu    sync.Mutex
	cache map[string]orgCacheEntry
}

// NewOrgGuard creates an OrgGuard backed by the organizations collection in db.
func NewOrgGuard(db *mongo.Database, logger *zap.Logger) *OrgGuard {
	return &OrgGuard{
		logger: logger,
		cache:  make(map[string]orgCacheEntry),
		lookup: func(ctx context.Context, orgID string) bool {
			err := db.Collection(CollectionOrganizations).
				FindOne(ctx, bson.M{"_id": orgID}).Err()
			if err != nil && err != mongo.ErrNoDocuments {
				// Real error (not "no such org"). Log it and fail open (treat
				// the org as present) so a transient DB blip does not silently
				// drop legitimate scan results.
				logger.Warn("Org existence check failed, treating org as present",
					zap.String("org_id", orgID),
					zap.Error(err),
				)
			}
			return err != mongo.ErrNoDocuments
		},
	}
}

// Exists reports whether the organization still exists. Results (both positive
// and negative) are cached for OrgCacheTTL. An empty orgID is always false.
func (g *OrgGuard) Exists(ctx context.Context, orgID string) bool {
	if orgID == "" {
		return false
	}

	now := time.Now()

	g.mu.Lock()
	if entry, ok := g.cache[orgID]; ok && now.Sub(entry.checkedAt) < OrgCacheTTL {
		g.mu.Unlock()
		return entry.exists
	}
	g.mu.Unlock()

	exists := g.lookup(ctx, orgID)

	g.mu.Lock()
	g.cache[orgID] = orgCacheEntry{exists: exists, checkedAt: now}
	g.mu.Unlock()

	return exists
}
