package shared

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

// TestOrgIDFilter locks the ObjectID conversion: organizations._id is an
// ObjectID, so a hex org id must produce an ObjectID filter (a bare string never
// matches and silently reads as "org not found" — the scan-trigger 404 bug).
// Non-hex ids fall back to a string match.
func TestOrgIDFilter(t *testing.T) {
	t.Parallel()

	const hexID = "507f191e810c19729de860ea"

	oid, err := primitive.ObjectIDFromHex(hexID)
	if err != nil {
		t.Fatalf("test setup: %v", err)
	}

	if got := OrgIDFilter(hexID)["_id"]; got != oid {
		t.Errorf("OrgIDFilter(%q)[_id] = %v (%T), want ObjectID %v", hexID, got, got, oid)
	}

	const notHex = "org-123"
	if got := OrgIDFilter(notHex)["_id"]; got != notHex {
		t.Errorf("OrgIDFilter(%q)[_id] = %v (%T), want string %q", notHex, got, got, notHex)
	}
}

// TestOrgGuardExists verifies the cache logic of OrgGuard without a MongoDB
// dependency by injecting a counting lookup func via the unexported seam. It
// asserts that the underlying lookup is invoked the expected number of times
// for cache hits, misses, TTL expiry, and both positive and negative caching.
func TestOrgGuardExists(t *testing.T) {
	t.Parallel()

	const orgID = "org-123"

	// rewindBetweenTTLs is older than the short positive TTL but younger than
	// the long negative TTL, so it proves the split: a positive entry goes
	// stale (re-lookup) while a negative entry of the same age stays fresh.
	const rewindBetweenTTLs = OrgPositiveCacheTTL + 15*time.Second // 45s: >30s, <5m

	tests := []struct {
		name           string
		orgID          string
		lookupResult   bool          // value the injected lookup returns
		calls          int           // number of back-to-back Exists invocations
		rewindAfter1   time.Duration // if >0, age the cached entry by this after the 1st call
		wantResult     bool
		wantLookupHits int
	}{
		{
			name:           "empty org id short-circuits without lookup",
			orgID:          "",
			lookupResult:   true,
			calls:          1,
			wantResult:     false,
			wantLookupHits: 0,
		},
		{
			name:           "positive result is cached across calls",
			orgID:          orgID,
			lookupResult:   true,
			calls:          3,
			wantResult:     true,
			wantLookupHits: 1,
		},
		{
			name:           "negative result is cached across calls",
			orgID:          orgID,
			lookupResult:   false,
			calls:          3,
			wantResult:     false,
			wantLookupHits: 1,
		},
		{
			name:           "expired entry triggers a fresh lookup",
			orgID:          orgID,
			lookupResult:   true,
			calls:          2,
			rewindAfter1:   2 * OrgCacheTTL,
			wantResult:     true,
			wantLookupHits: 2,
		},
		{
			name:           "positive entry expires after short TTL",
			orgID:          orgID,
			lookupResult:   true,
			calls:          2,
			rewindAfter1:   rewindBetweenTTLs, // older than positive TTL -> re-lookup
			wantResult:     true,
			wantLookupHits: 2,
		},
		{
			name:           "negative entry survives past short TTL",
			orgID:          orgID,
			lookupResult:   false,
			calls:          2,
			rewindAfter1:   rewindBetweenTTLs, // younger than negative TTL -> cached
			wantResult:     false,
			wantLookupHits: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			lookupHits := 0
			g := &OrgGuard{
				logger: zap.NewNop(),
				cache:  make(map[string]orgCacheEntry),
				lookup: func(_ context.Context, _ string) bool {
					lookupHits++
					return tc.lookupResult
				},
			}

			ctx := context.Background()
			var got bool
			for i := 0; i < tc.calls; i++ {
				got = g.Exists(ctx, tc.orgID)

				if tc.rewindAfter1 > 0 && i == 0 {
					// Age the cached timestamp so the next call re-evaluates
					// freshness against the entry's TTL.
					g.mu.Lock()
					entry := g.cache[tc.orgID]
					entry.checkedAt = time.Now().Add(-tc.rewindAfter1)
					g.cache[tc.orgID] = entry
					g.mu.Unlock()
				}
			}

			if got != tc.wantResult {
				t.Errorf("Exists(%q) = %v, want %v", tc.orgID, got, tc.wantResult)
			}
			if lookupHits != tc.wantLookupHits {
				t.Errorf("lookup called %d times, want %d", lookupHits, tc.wantLookupHits)
			}
		})
	}
}
