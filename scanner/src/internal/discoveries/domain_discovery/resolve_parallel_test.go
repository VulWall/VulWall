package domain_discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"go.uber.org/zap"
)

// fakeDNS answers name-N with a public address, except: names ending in "-priv" get a private
// answer mixed in, and names ending in "-nx" fail. It records the peak number of lookups in
// flight.
type fakeDNS struct {
	delay    time.Duration
	inFlight atomic.Int64
	peak     atomic.Int64
}

func (f *fakeDNS) lookup(ctx context.Context, host string) ([]net.IP, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	switch {
	case len(host) > 3 && host[len(host)-3:] == "-nx":
		return nil, errors.New("no such host")
	case len(host) > 5 && host[len(host)-5:] == "-priv":
		return parseIPs("93.184.216.34", "10.0.0.1"), nil
	}
	return parseIPs("93.184.216.34"), nil
}

type collected struct {
	mu    sync.Mutex
	hosts []string
}

func (c *collected) add(host, _ string) {
	c.mu.Lock()
	c.hosts = append(c.hosts, host)
	c.mu.Unlock()
}

func (c *collected) sorted() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]string(nil), c.hosts...)
	sort.Strings(out)
	return out
}

func TestResolvePublic_AllNamesAndPrivateFiltering(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")
	var names, want []string
	for i := range 300 {
		switch i % 3 {
		case 0:
			names = append(names, fmt.Sprintf("h%03d", i))
			want = append(want, fmt.Sprintf("h%03d", i))
		case 1:
			names = append(names, fmt.Sprintf("h%03d-priv", i))
		case 2:
			names = append(names, fmt.Sprintf("h%03d-nx", i))
		}
	}
	dns := &fakeDNS{delay: time.Millisecond}
	var got collected

	if err := resolvePublic(context.Background(), names, 16, dns.lookup, got.add, zap.NewNop()); err != nil {
		t.Fatal(err)
	}

	if g := got.sorted(); fmt.Sprint(g) != fmt.Sprint(want) {
		t.Fatalf("found %d names, want %d public ones: %v", len(g), len(want), g)
	}
}

func TestResolvePublic_AllowPrivateTargetsKeepsPrivateNames(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	var got collected
	names := []string{"a-priv", "b", "c-nx"}

	if err := resolvePublic(context.Background(), names, 4, (&fakeDNS{}).lookup, got.add, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if g := got.sorted(); fmt.Sprint(g) != "[a-priv b]" {
		t.Fatalf("found %v, want [a-priv b]", g)
	}
}

func TestResolvePublic_ConcurrencyBound(t *testing.T) {
	for _, workers := range []int{1, 7, 50} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			names := make([]string, 200)
			for i := range names {
				names[i] = fmt.Sprintf("h%d", i)
			}
			dns := &fakeDNS{delay: 2 * time.Millisecond}
			var got collected

			if err := resolvePublic(context.Background(), names, workers, dns.lookup, got.add, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			if peak := dns.peak.Load(); peak != int64(workers) {
				t.Fatalf("peak lookups in flight = %d, want exactly %d", peak, workers)
			}
			if n := len(got.sorted()); n != len(names) {
				t.Fatalf("found %d names, want %d", n, len(names))
			}
		})
	}
}

// The consumer ACKs the job when the handler returns, so no publish may happen after
// resolvePublic returns — also not when the context is cancelled halfway.
func TestResolvePublic_NoPublishAfterReturn(t *testing.T) {
	for _, cancelHalfway := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelHalfway), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			names := make([]string, 500)
			for i := range names {
				names[i] = fmt.Sprintf("h%d", i)
			}
			var returned atomic.Bool
			var late, calls atomic.Int64
			found := func(string, string) {
				time.Sleep(200 * time.Microsecond) // a slow publish
				if returned.Load() {
					late.Add(1)
				}
				if calls.Add(1) == 100 && cancelHalfway {
					cancel()
				}
			}

			err := resolvePublic(ctx, names, 20, (&fakeDNS{delay: time.Millisecond}).lookup, found, zap.NewNop())
			returned.Store(true)
			time.Sleep(20 * time.Millisecond) // give a stray worker the chance to publish late

			if late.Load() != 0 {
				t.Fatalf("%d publishes happened after resolvePublic returned", late.Load())
			}
			if cancelHalfway {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("err = %v, want context.Canceled", err)
				}
				if calls.Load() >= int64(len(names)) {
					t.Fatalf("published all %d names despite cancellation", calls.Load())
				}
			} else if err != nil || calls.Load() != int64(len(names)) {
				t.Fatalf("err = %v, published %d; want nil, %d", err, calls.Load(), len(names))
			}
		})
	}
}
