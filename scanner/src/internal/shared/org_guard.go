package shared

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// OrgIDFilter builds a MongoDB `_id` filter for an organization from its id
// string. The organizations collection keys on an ObjectID `_id`, so a bare
// string filter (`{_id: "69cd..."}`) matches nothing — the driver compares BSON
// types and string != ObjectID. Reads decode the ObjectID into the string `ID`
// field fine, which is why the scheduler (which loads orgs, not looks them up by
// id) worked while every by-id existence check silently returned "not found".
// Valid 24-char hex ids are converted to an ObjectID; anything else falls back
// to a string match so a non-hex legacy id still resolves.
func OrgIDFilter(orgID string) bson.M {
	return ObjectIDFilter(orgID)
}

// ObjectIDFilter is the `_id` filter of a document whose `_id` is an ObjectID that the
// scanner holds as hex (organizations, assets), with OrgIDFilter's fallback to a string match.
func ObjectIDFilter(id string) bson.M {
	if oid, err := primitive.ObjectIDFromHex(id); err == nil {
		return bson.M{"_id": oid}
	}
	return bson.M{"_id": id}
}

// OrgCacheTTL controls how long a NEGATIVE org-existence result (org does not
// exist) is cached before it is re-checked against MongoDB. It is long because
// a deleted org whose scan is still in flight would otherwise trigger a MongoDB
// lookup for every orphan result in the drain.
const OrgCacheTTL = 5 * time.Minute

// OrgPositiveCacheTTL controls how long a POSITIVE result (org exists) is
// cached. It is deliberately short: an org can be deleted mid-scan, and a long
// positive TTL would keep writing orphan results until it expired — defeating
// the guard. A per-org FindOne on _id is an indexed point lookup, so a short
// TTL still collapses bursts while tightening the orphan window to ~30s.
const OrgPositiveCacheTTL = 30 * time.Second

// orgCacheEntry is a single cached org-existence result.
type orgCacheEntry struct {
	exists    bool
	checkedAt time.Time
}

// ttl returns how long this entry stays fresh: short for positive results
// (catch mid-scan deletes fast), long for negatives (avoid orphan-drain churn).
func (e orgCacheEntry) ttl() time.Duration {
	if e.exists {
		return OrgPositiveCacheTTL
	}
	return OrgCacheTTL
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
				FindOne(ctx, OrgIDFilter(orgID)).Err()
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

// Exists reports whether the organization still exists. Positive results are
// cached for OrgPositiveCacheTTL (short, so a mid-scan delete is caught
// quickly); negative results are cached for OrgCacheTTL (long, to avoid
// hammering MongoDB during an orphan drain). An empty orgID is always false.
func (g *OrgGuard) Exists(ctx context.Context, orgID string) bool {
	if orgID == "" {
		return false
	}

	now := time.Now()

	g.mu.Lock()
	if entry, ok := g.cache[orgID]; ok && now.Sub(entry.checkedAt) < entry.ttl() {
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
