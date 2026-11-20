package telemetry

import (
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func TestTracingIsOptIn(t *testing.T) {
	for value, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true} {
		t.Setenv(config.EnvOTELEnabled, value)
		if got := isTracingEnabled(); got != want {
			t.Errorf("OTEL_ENABLED=%q: enabled = %v, want %v", value, got, want)
		}
	}
}
