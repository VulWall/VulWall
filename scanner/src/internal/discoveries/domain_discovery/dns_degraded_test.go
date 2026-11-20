package domain_discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"go.uber.org/zap"
)

func TestIsLookupFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"NXDOMAIN is a clean answer", &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"wrapped NXDOMAIN is a clean answer", fmt.Errorf("lookup: %w", &net.DNSError{IsNotFound: true}), false},
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, true},
		{"SERVFAIL", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		{"refused / network error", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"unknown error", errors.New("boom"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isLookupFailure(tt.err); got != tt.want {
				t.Errorf("isLookupFailure(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDNSDegraded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		names      int
		failures   int
		rootFailed bool
		want       bool
	}{
		{"clean run", 200, 0, false, false},
		{"root failed alone degrades", 0, 0, true, true},
		{"root failed with clean subdomains degrades", 200, 0, true, true},
		{"exactly 20% is tolerated", 200, 40, false, false},
		{"just over 20% degrades", 200, 41, false, true},
		{"all failed but only 50 names is tolerated", 50, 50, false, false},
		{"51 names, 11 failed degrades", 51, 11, false, true},
		{"51 names, 10 failed is tolerated", 51, 10, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := dnsDegraded(tt.names, tt.failures, tt.rootFailed); got != tt.want {
				t.Errorf("dnsDegraded(%d, %d, %v) = %v, want %v",
					tt.names, tt.failures, tt.rootFailed, got, tt.want)
			}
		})
	}
}

// TestResolvePublic_CountsOnlyLookupFailures checks that names the resolver could not answer
// are counted, while names that cleanly do not exist (NXDOMAIN) or resolve to a private
// address are not.
func TestResolvePublic_CountsOnlyLookupFailures(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")

	var names []string
	for i := range 120 {
		switch i % 4 {
		case 0:
			names = append(names, fmt.Sprintf("h%03d", i))
		case 1:
			names = append(names, fmt.Sprintf("h%03d-nx", i))
		case 2:
			names = append(names, fmt.Sprintf("h%03d-priv", i))
		case 3:
			names = append(names, fmt.Sprintf("h%03d-fail", i))
		}
	}
	got := &collected{}
	failures, err := resolvePublic(context.Background(), names, 8, (&fakeDNS{}).lookup, got.add, zap.NewNop())
	if err != nil {
		t.Fatalf("resolvePublic: %v", err)
	}
	if failures != 30 {
		t.Errorf("failures = %d, want 30 (only the -fail names)", failures)
	}
	if n := len(got.sorted()); n != 30 {
		t.Errorf("published %d names, want 30", n)
	}
	if !dnsDegraded(len(names), failures, false) {
		t.Errorf("120 names with 30 failures (25%%) should be degraded")
	}
}
