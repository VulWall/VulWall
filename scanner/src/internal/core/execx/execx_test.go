package execx

import (
	"context"
	"testing"
	"time"
)

// TestCancelKillsProcessGroup starts a shell whose background child keeps the
// output pipe open. Cancelling must return quickly, because the whole group
// is killed, not only the shell.
func TestCancelKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := Command(ctx, "sh", "-c", "sleep 30 & sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	cancel()
	_ = cmd.Wait()

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Wait returned after %v; the process group was not killed", elapsed)
	}
}
