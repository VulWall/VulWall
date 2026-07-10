package scan_coordinator

import (
	"testing"
	"time"
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
			complete, reason, timedOut := decideCompletion(tt.scanAge, tt.lastActivity, tt.quiescent, now)
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
