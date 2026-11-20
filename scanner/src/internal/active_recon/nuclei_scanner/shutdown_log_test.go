package nuclei_scanner

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// A run cut off by shutdown is normal: it must log at Info, not Error (Error carries a stack
// trace in production).
func TestProcessDiscoveryLogsShutdownAtInfo(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	s := &Service{logger: zap.New(core), tracer: otel.Tracer("nuclei-scanner")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := s.ProcessDiscovery(ctx, ScanTarget{Target: "example.com", OrgID: "org"})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); n != 0 {
		t.Fatalf("%d Error entries, want none: %v", n, logs.FilterLevelExact(zapcore.ErrorLevel).All())
	}
	if logs.FilterMessageSnippet("stopped by shutdown").FilterLevelExact(zapcore.InfoLevel).Len() != 1 {
		t.Fatalf("want one Info 'stopped by shutdown' entry, got %v", logs.All())
	}
}
