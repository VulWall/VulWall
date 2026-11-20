package redisx

import (
	"context"
	"errors"
	"testing"

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

func TestProcessMessageAcksSuccessAndHandlerError(t *testing.T) {
	for name, handlerErr := range map[string]error{"success": nil, "error": errors.New("bad payload")} {
		t.Run(name, func(t *testing.T) {
			var acked []string
			handler := func(context.Context, redis.XMessage) error { return handlerErr }

			processMessage(context.Background(), handler, recordAck(&acked), zap.NewNop(), redis.XMessage{ID: "1-0"})

			if len(acked) != 1 || acked[0] != "1-0" {
				t.Fatalf("acked = %v, want [1-0]", acked)
			}
		})
	}
}

func TestProcessMessageRecoversPanicLogsStackAndAcks(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	var acked []string
	handler := func(context.Context, redis.XMessage) error { panic("nil map write") }

	processMessage(context.Background(), handler, recordAck(&acked), zap.New(core), redis.XMessage{ID: "2-0"})

	if len(acked) != 1 || acked[0] != "2-0" {
		t.Fatalf("acked = %v, want the poisoned message ACKed", acked)
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
	var acked []string
	handler := func(ctx context.Context, _ redis.XMessage) error {
		cancel() // shutdown arrives while the handler runs
		return ctx.Err()
	}

	processMessage(ctx, handler, recordAck(&acked), zap.NewNop(), redis.XMessage{ID: "3-0"})

	if len(acked) != 0 {
		t.Fatalf("acked = %v, want none: the work was cut off by shutdown", acked)
	}
}

func TestProcessMessageAcksSuccessDuringShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var acked []string
	handler := func(context.Context, redis.XMessage) error {
		cancel() // shutdown starts just as the handler finishes its work
		return nil
	}

	processMessage(ctx, handler, recordAck(&acked), zap.NewNop(), redis.XMessage{ID: "4-0"})

	if len(acked) != 1 {
		t.Fatalf("acked = %v, want the finished message ACKed with a detached context", acked)
	}
}
