package scan_coordinator

import (
	"context"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.uber.org/zap"
)

// TestGroupQuiescent pins the leaf drain predicate: a group is quiescent only when it has
// nothing pending (read-but-unacked) AND has delivered up to the stream's last-generated id.
func TestGroupQuiescent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		pending       int64
		lastDelivered string
		lastGenerated string
		want          bool
	}{
		{"pending blocks even when caught up", 1, "5-0", "5-0", false},
		{"undelivered entries block", 0, "4-0", "5-0", false},
		{"drained and caught up", 0, "5-0", "5-0", true},
		{"empty stream is quiescent", 0, "0-0", "0-0", true},
		{"pending and behind", 3, "2-0", "5-0", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := groupQuiescent(tt.pending, tt.lastDelivered, tt.lastGenerated); got != tt.want {
				t.Errorf("groupQuiescent(%d, %q, %q) = %v, want %v",
					tt.pending, tt.lastDelivered, tt.lastGenerated, got, tt.want)
			}
		})
	}
}

// TestDecideCompletion is the full completion truth table. The most important row is the
// regression lock: a young scan is NEVER completed by the quiescence path, even when the
// pipeline momentarily reads as quiescent — that transient dead-zone is exactly what marked
// the real scans "done" ~30s in.
func TestDecideCompletion(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	tests := []struct {
		name         string
		scanAge      time.Duration
		lastActivity *time.Time
		quiescent    bool
		inFlight     bool
		wantComplete bool
		wantReason   string
		wantTimedOut bool
	}{
		{
			name:         "safety timeout dominates regardless of everything else",
			scanAge:      ScanSafetyTimeout + time.Minute,
			lastActivity: nil,
			quiescent:    false,
			wantComplete: true,
			wantReason:   "safety_timeout",
			wantTimedOut: true,
		},
		{
			name:         "REGRESSION: young scan reading quiescent is NOT completed",
			scanAge:      30 * time.Second,
			lastActivity: ago(30 * time.Second),
			quiescent:    true,
			wantComplete: false,
		},
		{
			name:         "quiescent, past min runtime, settled -> complete",
			scanAge:      ScanMinRuntime + time.Minute,
			lastActivity: ago(ScanSettleGrace + 10*time.Second),
			quiescent:    true,
			wantComplete: true,
			wantReason:   "pipeline_quiescent",
			wantTimedOut: false,
		},
		{
			name:         "quiescent but activity within settle grace -> not complete",
			scanAge:      ScanMinRuntime + time.Minute,
			lastActivity: ago(ScanSettleGrace - 10*time.Second),
			quiescent:    true,
			wantComplete: false,
		},
		{
			name:         "not quiescent but idle past timeout -> idle backstop completes",
			scanAge:      ScanMinRuntime + ScanIdleTimeout + time.Minute,
			lastActivity: ago(ScanIdleTimeout + time.Minute),
			quiescent:    false,
			wantComplete: true,
			wantReason:   "idle_timeout",
			wantTimedOut: false,
		},
		{
			name:         "idle past timeout but a discovery job is in flight -> not complete",
			scanAge:      ScanMinRuntime + ScanIdleTimeout + time.Minute,
			lastActivity: ago(ScanIdleTimeout + time.Minute),
			quiescent:    false,
			inFlight:     true,
			wantComplete: false,
		},
		{
			name:         "in flight does not hold back the safety timeout",
			scanAge:      ScanSafetyTimeout + time.Minute,
			lastActivity: ago(ScanIdleTimeout + time.Minute),
			inFlight:     true,
			wantComplete: true,
			wantReason:   "safety_timeout",
			wantTimedOut: true,
		},
		{
			name:         "not quiescent, idle below timeout -> not complete",
			scanAge:      ScanMinRuntime + time.Minute,
			lastActivity: ago(2 * time.Minute),
			quiescent:    false,
			wantComplete: false,
		},
		{
			name:         "no activity ever, past min runtime, quiescent -> not complete (guards need activity)",
			scanAge:      ScanMinRuntime + 5*time.Minute,
			lastActivity: nil,
			quiescent:    true,
			wantComplete: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			complete, reason, timedOut := defaultCompletionPolicy().decideCompletion(tt.scanAge, tt.lastActivity, tt.quiescent, tt.inFlight, now)
			if complete != tt.wantComplete {
				t.Fatalf("complete = %v, want %v (reason=%q)", complete, tt.wantComplete, reason)
			}
			if !complete {
				return
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
			if timedOut != tt.wantTimedOut {
				t.Errorf("timedOut = %v, want %v", timedOut, tt.wantTimedOut)
			}
		})
	}
}

// fakeStreams.pendingIdle serves the per-entry idle times set in pending.
func (f *fakeStreams) pendingIdle(_ context.Context, stream, group string, count int64) ([]time.Duration, error) {
	idles := f.pending[StreamGroup{stream, group}]
	return idles[:min(int64(len(idles)), count)], nil
}

func withPending(f *fakeStreams, sg StreamGroup, idles ...time.Duration) {
	if f.pending == nil {
		f.pending = map[StreamGroup][]time.Duration{}
	}
	f.pending[sg] = idles
	g := f.groupz[sg.Stream][sg.Group]
	g.Pending = int64(len(idles))
	f.groupz[sg.Stream][sg.Group] = g
}

func TestFreshPendingWork(t *testing.T) {
	discovery := StreamGroup{shared.StreamDomainDiscoveryQueue, "domain_discovery_service"}
	nuclei := StreamGroup{shared.StreamDomainScanTriggers, "nuclei_scanner_service"}
	stuck := ScanStuckThreshold

	tests := []struct {
		name    string
		setup   func(*fakeStreams)
		want    *StreamGroup
		wantMin time.Duration
	}{
		{"nothing pending", func(*fakeStreams) {}, nil, 0},
		{"discovery job running for 12 minutes", func(f *fakeStreams) {
			withPending(f, discovery, 12*time.Minute)
		}, &discovery, 12 * time.Minute},
		{"discovery job pending past the stuck threshold", func(f *fakeStreams) {
			withPending(f, discovery, stuck+time.Minute)
		}, nil, 0},
		{"read-ahead entries are old but one was delivered recently", func(f *fakeStreams) {
			withPending(f, nuclei, stuck+time.Hour, 2*time.Minute, stuck+time.Minute)
		}, &nuclei, 2 * time.Minute},
		{"stuck upstream, fresh downstream", func(f *fakeStreams) {
			withPending(f, discovery, stuck+time.Minute)
			withPending(f, nuclei, time.Minute)
		}, &nuclei, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := drainedPipeline()
			tt.setup(f)

			got, err := freshPendingWork(context.Background(), f, scanPipelineGroups(), stuck)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("got %+v, want no work in flight", got)
			case tt.want != nil && (got == nil || got.StreamGroup != *tt.want || got.YoungestIdle != tt.wantMin):
				t.Fatalf("got %+v, want %+v with youngest idle %v", got, *tt.want, tt.wantMin)
			}
		})
	}
}

func TestLoadCompletionPolicy(t *testing.T) {
	t.Setenv("SCAN_IDLE_TIMEOUT", "2m")
	t.Setenv("SCAN_MIN_RUNTIME", "1m")
	p := loadCompletionPolicy(zap.NewNop())
	if p.idleTimeout != 2*time.Minute || p.minRuntime != time.Minute {
		t.Fatalf("policy = %+v, want idle 2m, min runtime 1m", p)
	}
	if p.settleGrace != ScanSettleGrace || p.stuckAfter != ScanStuckThreshold || p.safetyTimeout != ScanSafetyTimeout {
		t.Fatalf("policy = %+v, other thresholds must keep their defaults", p)
	}

	for _, bad := range []string{"15", "-1m", "0s", "soon"} {
		t.Setenv("SCAN_IDLE_TIMEOUT", bad)
		if got := loadCompletionPolicy(zap.NewNop()).idleTimeout; got != ScanIdleTimeout {
			t.Errorf("SCAN_IDLE_TIMEOUT=%q gave %v, want the default %v", bad, got, ScanIdleTimeout)
		}
	}
}
