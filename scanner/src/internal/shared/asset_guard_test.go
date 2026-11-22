package shared

import (
	"context"
	"testing"
	"time"
)

// AssetGuard caches like OrgGuard, per (org, asset): an id of another org is its own entry.
func TestAssetGuardExists(t *testing.T) {
	hits := map[assetKey]int{}
	g := &AssetGuard{
		cache: make(map[assetKey]orgCacheEntry),
		lookup: func(_ context.Context, orgID, assetID string) bool {
			hits[assetKey{orgID, assetID}]++
			return orgID == "org-1" && assetID == "live"
		},
	}
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if !g.Exists(ctx, "org-1", "live") {
			t.Fatal("live asset reported missing")
		}
		if g.Exists(ctx, "org-1", "gone") {
			t.Fatal("deleted asset reported present")
		}
		if g.Exists(ctx, "org-2", "live") {
			t.Fatal("asset of another org reported present")
		}
	}
	if g.Exists(ctx, "", "live") || g.Exists(ctx, "org-1", "") {
		t.Fatal("empty org or asset id reported present")
	}
	for k, n := range hits {
		if n != 1 {
			t.Errorf("lookup of %v ran %d times, want 1 (cached)", k, n)
		}
	}
	if len(hits) != 3 {
		t.Errorf("%d lookups, want 3 (empty ids never look up)", len(hits))
	}

	// A positive entry expires after OrgPositiveCacheTTL, a negative one stays for OrgCacheTTL.
	age := OrgPositiveCacheTTL + time.Second
	g.mu.Lock()
	for k, e := range g.cache {
		e.checkedAt = time.Now().Add(-age)
		g.cache[k] = e
	}
	g.mu.Unlock()
	g.Exists(ctx, "org-1", "live")
	g.Exists(ctx, "org-1", "gone")
	if hits[assetKey{"org-1", "live"}] != 2 {
		t.Error("stale positive entry was not looked up again")
	}
	if hits[assetKey{"org-1", "gone"}] != 1 {
		t.Error("negative entry was looked up again before OrgCacheTTL")
	}
}
