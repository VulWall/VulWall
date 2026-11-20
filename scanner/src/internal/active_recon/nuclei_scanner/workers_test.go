package nuclei_scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func TestWorkersLimitScansAcrossStreams(t *testing.T) {
	t.Setenv(config.EnvNucleiWorkers, "2")
	c := NewConsumer(nil, zap.NewNop())

	var running, peak atomic.Int32
	handler := func(context.Context, redis.XMessage) error {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return nil
	}
	// Two wrapped handlers stand for the domain and the port stream.
	domain, port := c.limited(handler), c.limited(handler)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = domain(context.Background(), redis.XMessage{}) }()
		go func() { defer wg.Done(); _ = port(context.Background(), redis.XMessage{}) }()
	}
	wg.Wait()

	if got := peak.Load(); got != 2 {
		t.Fatalf("peak concurrent scans = %d, want 2", got)
	}
}

func TestTemplatesDirOverride(t *testing.T) {
	t.Setenv(config.EnvNucleiTemplatesDir, "/data/nuclei-templates")
	if got := templatesDir(); got != "/data/nuclei-templates" {
		t.Fatalf("templatesDir() = %q", got)
	}
}
