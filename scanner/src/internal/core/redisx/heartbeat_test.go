package redisx

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// TestLongHandlerKeepsPendingEntryFresh checks against a real Redis (VULWALL_TEST_REDIS_URI)
// that while a handler runs, its pending entry's idle time keeps being reset, without adding
// deliveries, so the scan monitor does not read a long nuclei run as stuck.
func TestLongHandlerKeepsPendingEntryFresh(t *testing.T) {
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
	old := pendingHeartbeat
	pendingHeartbeat = 100 * time.Millisecond
	t.Cleanup(func() { pendingHeartbeat = old })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, group := "test_heartbeat_stream", "test_heartbeat_group"
	rdb.Del(ctx, stream)
	t.Cleanup(func() { rdb.Del(context.Background(), stream) })
	if err := CreateConsumerGroup(ctx, rdb, stream, group); err != nil {
		t.Fatal(err)
	}
	if err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]any{"data": "{}"}}).Err(); err != nil {
		t.Fatal(err)
	}

	started, release, handled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go ConsumeStream(ctx, rdb, ConsumerConfig{
		Stream: stream, Group: group, ConsumerPrefix: "hb", Logger: zap.NewNop(),
		Handler: func(ctx context.Context, _ redis.XMessage) error {
			close(started)
			<-release // a long nuclei run
			return nil
		},
	})
	go func() {
		<-started
		time.Sleep(time.Second)
		pending, err := rdb.XPendingExt(ctx, &redis.XPendingExtArgs{Stream: stream, Group: group, Start: "-", End: "+", Count: 10}).Result()
		if err != nil || len(pending) != 1 {
			t.Errorf("pending = %v, %v; want one entry", pending, err)
		} else {
			// Without the heartbeat the entry would be idle for about 1 s.
			if pending[0].Idle > 400*time.Millisecond {
				t.Errorf("idle = %v while the handler runs, want it kept below 400ms", pending[0].Idle)
			}
			if pending[0].RetryCount != 1 {
				t.Errorf("delivery count = %d, want 1 (a heartbeat is not a delivery)", pending[0].RetryCount)
			}
		}
		close(release)
		close(handled)
	}()

	select {
	case <-handled:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not run")
	}
	// After the handler the message is ACKed and no late beat brings it back.
	deadline := time.Now().Add(2 * time.Second)
	for {
		n, err := rdb.XPending(ctx, stream, group).Result()
		if err == nil && n.Count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending after the handler = %+v, %v; want none", n, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n, _ := rdb.XPending(ctx, stream, group).Result(); n.Count != 0 {
		t.Fatalf("pending = %d after a late heartbeat, want 0", n.Count)
	}
}
