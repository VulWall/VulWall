// Package execx runs external scanner tools (nuclei, testssl.sh, retire).
package execx

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// waitDelay bounds how long Wait blocks on output pipes that orphaned
// grandchildren still hold after the tool was killed.
const waitDelay = 5 * time.Second

// Command is exec.CommandContext with the tool in its own process group.
//
// All components share one process. Without a separate group, a tool that
// signals its process group (testssl.sh and its helpers do) can kill the
// scanner itself, and grandchildren survive when only the direct child is
// killed. On ctx cancellation the whole group gets SIGKILL.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
	return cmd
}
