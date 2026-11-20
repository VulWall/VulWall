package redisx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// recordAck returns an ack func that records the IDs it ACKed and whether its
// context was already cancelled.
func recordAck(acked *[]string) func(context.Context, string) error {
	return func(ctx context.Context, id string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		*acked = append(*acked, id)
		return nil
	}
}

// recordDeadLetter returns a dead-letter func that records the IDs it received.
func recordDeadLetter(dead *[]string) func(context.Context, redis.XMessage, error) error {
	return func(_ context.Context, m redis.XMessage, _ error) error {
		*dead = append(*dead, m.ID)
		return nil
	}
}

// fastRetries shortens the retry delay for the test.
func fastRetries(t *testing.T) {
	t.Helper()
	old := handlerRetryDelay
	handlerRetryDelay = time.Millisecond
	t.Cleanup(func() { handlerRetryDelay = old })
}

func TestProcessMessageAcksSuccessOnce(t *testing.T) {
	var acked, dead []string
	calls := 0
	handler := func(context.Context, redis.XMessage) error { calls++; return nil }

	processMessage(context.Background(), handler, recordAck(&acked), recordDeadLetter(&dead), zap.NewNop(), redis.XMessage{ID: "1-0"})

	if calls != 1 || len(acked) != 1 || len(dead) != 0 {
		t.Fatalf("calls=%d acked=%v dead=%v, want 1 call, ACKed, not dead-lettered", calls, acked, dead)
	}
}

func TestProcessMessageRetriesTransientErrorUntilSuccess(t *testing.T) {
	fastRetries(t)
	var acked, dead []string
	calls := 0
	handler := func(context.Context, redis.XMessage) error {
		calls++
		if calls < handlerAttempts {
			return errors.New("redis down")
		}
		return nil
	}

	processMessage(context.Background(), handler, recordAck(&acked), recordDeadLetter(&dead), zap.NewNop(), redis.XMessage{ID: "1-0"})

	if calls != handlerAttempts || len(acked) != 1 || len(dead) != 0 {
		t.Fatalf("calls=%d acked=%v dead=%v, want %d calls, ACKed once, not dead-lettered", calls, acked, dead, handlerAttempts)
	}
}

func TestProcessMessageDeadLettersAfterMaxAttempts(t *testing.T) {
	fastRetries(t)
	var acked, dead []string
	calls := 0
	handler := func(context.Context, redis.XMessage) error { calls++; return errors.New("still down") }

	processMessage(context.Background(), handler, recordAck(&acked), recordDeadLetter(&dead), zap.NewNop(), redis.XMessage{ID: "1-0"})

	if calls != handlerAttempts {
		t.Fatalf("calls = %d, want %d: the retries are bounded", calls, handlerAttempts)
	}
	if len(dead) != 1 || len(acked) != 1 {
		t.Fatalf("dead=%v acked=%v, want dead-lettered then ACKed", dead, acked)
	}
}

func TestProcessMessageDeadLettersPermanentErrorWithoutRetry(t *testing.T) {
	var acked, dead []string
	calls := 0
	handler := func(context.Context, redis.XMessage) error { calls++; return Permanent(errors.New("bad json")) }

	processMessage(context.Background(), handler, recordAck(&acked), recordDeadLetter(&dead), zap.NewNop(), redis.XMessage{ID: "1-0"})

	if calls != 1 || len(dead) != 1 || len(acked) != 1 {
		t.Fatalf("calls=%d dead=%v acked=%v, want 1 call, dead-lettered, ACKed", calls, dead, acked)
	}
}

func TestProcessMessageShutdownDuringBackoffLeavesUnacked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var acked, dead []string
	handler := func(context.Context, redis.XMessage) error {
		cancel() // shutdown arrives after the failure, before the retry
		return errors.New("redis down")
	}
	// The handler error is checked against ctx first, so cancel after returning is
	// seen as shutdown either way; both paths must leave the message pending.
	processMessage(ctx, handler, recordAck(&acked), recordDeadLetter(&dead), zap.NewNop(), redis.XMessage{ID: "1-0"})

	if len(acked) != 0 || len(dead) != 0 {
		t.Fatalf("acked=%v dead=%v, want neither: shutdown leaves the message pending", acked, dead)
	}
}

func TestProcessMessageRecoversPanicLogsStackAndAcks(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	var acked []string
	handler := func(context.Context, redis.XMessage) error { panic("nil map write") }

	var dead []string
	processMessage(context.Background(), handler, recordAck(&acked), recordDeadLetter(&dead), zap.New(core), redis.XMessage{ID: "2-0"})

	if len(acked) != 1 || acked[0] != "2-0" || len(dead) != 1 {
		t.Fatalf("acked = %v dead = %v, want the poisoned message dead-lettered and ACKed", acked, dead)
	}
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("logged %d errors, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	if stack, _ := fields["stack"].(string); stack == "" {
		t.Errorf("log fields = %v, want a non-empty stack", fields)
	}
}

func TestProcessMessageLeavesCancelledWorkUnacked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	core, logs := observer.New(zap.DebugLevel)
	var acked []string
	handler := func(ctx context.Context, _ redis.XMessage) error {
		cancel() // shutdown arrives while the handler runs
		return ctx.Err()
	}

	processMessage(ctx, handler, recordAck(&acked), recordDeadLetter(new([]string)), zap.New(core), redis.XMessage{ID: "3-0"})

	if len(acked) != 0 {
		t.Fatalf("acked = %v, want none: the work was cut off by shutdown", acked)
	}
	if all := logs.All(); len(all) != 1 || all[0].Level != zap.InfoLevel {
		t.Fatalf("logs = %v, want one Info entry: shutdown is not a failure", all)
	}
}

func TestProcessMessageAcksSuccessDuringShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var acked []string
	handler := func(context.Context, redis.XMessage) error {
		cancel() // shutdown starts just as the handler finishes its work
		return nil
	}

	processMessage(ctx, handler, recordAck(&acked), recordDeadLetter(new([]string)), zap.NewNop(), redis.XMessage{ID: "4-0"})

	if len(acked) != 1 {
		t.Fatalf("acked = %v, want the finished message ACKed with a detached context", acked)
	}
}
