package domain_discovery

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A job cut off by shutdown returns the context error (so it is not ACKed) and is not logged
// as a failure.
func TestProcessMessage_ShutdownIsNotAnError(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	log := zap.New(core)
	// Nothing listens on port 1; with the context already cancelled the publish fails at once.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rdb.Close()
	c := &Consumer{logger: log, service: &Service{redis: rdb, logger: log, tracer: otel.Tracer("test")}}
	data, _ := json.Marshal(shared.DiscoveryJob{OrgID: "org", Host: "203.0.113.7"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := c.processMessage(ctx, redis.XMessage{ID: "1-0", Values: map[string]any{"data": string(data)}})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := logs.FilterMessage("Job processing failed").Len(); n != 0 {
		t.Fatalf("logged %d \"Job processing failed\" entries, want none", n)
	}
}
