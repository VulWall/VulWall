package email_security_scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func TestAXFRAddressRejectsReservedNameservers(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "false")
	for _, host := range []string{"127.0.0.1", "10.0.0.53", "169.254.169.254", "::1"} {
		if addr, err := axfrAddress(context.Background(), host); err == nil {
			t.Errorf("axfrAddress(%q) = %q, want an error", host, addr)
		}
	}
}

func TestAXFRAddressDialsValidatedPublicIP(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "false")
	addr, err := axfrAddress(context.Background(), "8.8.8.8")
	if err != nil || addr != "8.8.8.8:53" {
		t.Fatalf("axfrAddress = %q, %v; want 8.8.8.8:53", addr, err)
	}
}

func TestAXFRAddressHonorsAllowPrivateTargets(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	addr, err := axfrAddress(context.Background(), "10.0.0.53")
	if err != nil || addr != "10.0.0.53:53" {
		t.Fatalf("axfrAddress = %q, %v; want 10.0.0.53:53", addr, err)
	}
}

func TestAXFRFailureSeparatesRefusalFromUnknown(t *testing.T) {
	refused := &net.OpError{Op: "dial", Err: fmt.Errorf("connect: %w", syscall.ECONNREFUSED)}
	timeout := &net.OpError{Op: "read", Err: &timeoutErr{}}
	if axfrFailure(refused) != nil {
		t.Error("a refused connection is a definite no, want nil")
	}
	if axfrFailure(errors.New("dns: bad xfr rcode: 5")) != nil {
		t.Error("a REFUSED answer is a definite no, want nil")
	}
	if axfrFailure(timeout) == nil {
		t.Error("a timeout leaves the answer unknown, want an error")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
