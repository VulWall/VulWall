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
	stopped := make(chan struct{})
	// Stop the consumer before the cleanups restore pendingHeartbeat (cleanups run last-in first).
	t.Cleanup(func() { cancel(); <-stopped })
	go runConsumer(ctx, rdb, stopped, ConsumerConfig{
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

// TestBufferedMessageIsFreshWhenItsHandlerStarts checks against a real Redis that a message
// read ahead, which waited in the worker buffer behind a long handler, has its idle time reset
// as soon as its own handler starts, not one heartbeat later.
func TestBufferedMessageIsFreshWhenItsHandlerStarts(t *testing.T) {
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
	pendingHeartbeat = time.Hour // only the first, immediate beat can help
	t.Cleanup(func() { pendingHeartbeat = old })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, group := "test_heartbeat_buffer_stream", "test_heartbeat_buffer_group"
	rdb.Del(ctx, stream)
	t.Cleanup(func() { rdb.Del(context.Background(), stream) })
	if err := CreateConsumerGroup(ctx, rdb, stream, group); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for range 2 {
		id, err := rdb.XAdd(ctx, &redis.XAddArgs{Stream: stream, Values: map[string]any{"data": "{}"}}).Result()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	idleAtStart := make(chan time.Duration, 1)
	stopped := make(chan struct{})
	// Stop the consumer before the cleanups restore pendingHeartbeat (cleanups run last-in first).
	t.Cleanup(func() { cancel(); <-stopped })
	go runConsumer(ctx, rdb, stopped, ConsumerConfig{
		Stream: stream, Group: group, ConsumerPrefix: "hb", Logger: zap.NewNop(), BatchSize: 2,
		Handler: func(ctx context.Context, m redis.XMessage) error {
			if m.ID == ids[0] {
				time.Sleep(time.Second) // the second message waits in the buffer meanwhile
				return nil
			}
			p, err := rdb.XPendingExt(ctx, &redis.XPendingExtArgs{Stream: stream, Group: group, Start: m.ID, End: m.ID, Count: 1}).Result()
			if err != nil || len(p) != 1 {
				t.Errorf("pending of %s = %v, %v", m.ID, p, err)
				idleAtStart <- -1
				return nil
			}
			idleAtStart <- p[0].Idle
			return nil
		},
	})
	select {
	case idle := <-idleAtStart:
		// Without the immediate beat it would be about 1 s (the wait in the buffer).
		if idle < 0 || idle > 300*time.Millisecond {
			t.Fatalf("idle when the handler started = %v, want below 300ms", idle)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second handler did not run")
	}
}

func runConsumer(ctx context.Context, rdb *redis.Client, stopped chan struct{}, cfg ConsumerConfig) {
	defer close(stopped)
	_ = ConsumeStream(ctx, rdb, cfg)
}
