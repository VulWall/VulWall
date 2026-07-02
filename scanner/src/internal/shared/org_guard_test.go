package shared

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestOrgGuardExists verifies the cache logic of OrgGuard without a MongoDB
// dependency by injecting a counting lookup func via the unexported seam. It
// asserts that the underlying lookup is invoked the expected number of times
// for cache hits, misses, TTL expiry, and both positive and negative caching.
func TestOrgGuardExists(t *testing.T) {
	t.Parallel()

	const orgID = "org-123"

	tests := []struct {
		name          string
		orgID         string
		lookupResult  bool // value the injected lookup returns
		calls         int  // number of back-to-back Exists invocations
		expireAfter1  bool // force the cached entry to look stale after the 1st call
		wantResult    bool
		wantLookupHits int
	}{
		{
			name:          "empty org id short-circuits without lookup",
			orgID:         "",
			lookupResult:  true,
			calls:         1,
			wantResult:    false,
			wantLookupHits: 0,
		},
		{
			name:          "positive result is cached across calls",
			orgID:         orgID,
			lookupResult:  true,
			calls:         3,
			wantResult:    true,
			wantLookupHits: 1,
		},
		{
			name:          "negative result is cached across calls",
			orgID:         orgID,
			lookupResult:  false,
			calls:         3,
			wantResult:    false,
			wantLookupHits: 1,
		},
		{
			name:          "expired entry triggers a fresh lookup",
			orgID:         orgID,
			lookupResult:  true,
			calls:         2,
			expireAfter1:  true,
			wantResult:    true,
			wantLookupHits: 2,
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

				if tc.expireAfter1 && i == 0 {
					// Rewind the cached timestamp past the TTL so the next call
					// treats the entry as stale and re-runs the lookup.
					g.mu.Lock()
					entry := g.cache[tc.orgID]
					entry.checkedAt = time.Now().Add(-2 * OrgCacheTTL)
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
