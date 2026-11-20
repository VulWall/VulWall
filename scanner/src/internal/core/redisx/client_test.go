package redisx

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
)

// TestPublishDeadLetterIsCapped checks against a real Redis (VULWALL_TEST_REDIS_URI) that the
// dead-letter stream stays near deadLetterMaxLen.
func TestPublishDeadLetterIsCapped(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_REDIS_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	ctx := context.Background()
	rdb.Del(ctx, shared.StreamDeadLetter)
	defer rdb.Del(ctx, shared.StreamDeadLetter)

	const n = deadLetterMaxLen + 1000
	for i := 0; i < n; i++ {
		if err := PublishDeadLetter(ctx, rdb, "s", "g", "1-0", "{}", errors.New("boom")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := rdb.XLen(ctx, shared.StreamDeadLetter).Result()
	if err != nil {
		t.Fatal(err)
	}
	if got >= n || got < deadLetterMaxLen {
		t.Fatalf("XLEN = %d after %d entries, want trimmed to about %d", got, n, deadLetterMaxLen)
	}
}
