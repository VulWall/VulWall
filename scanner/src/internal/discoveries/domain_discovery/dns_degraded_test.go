package domain_discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
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

func TestDegradedReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rootReason string
		enumFailed bool
		names      int
		failures   int
		want       string
	}{
		{"clean run", "", false, 200, 0, ""},
		{"root without address but existing is clean", "", false, 0, 0, ""},
		{"root nxdomain", shared.ScanDegradedRootNXDOMAIN, false, 0, 0, shared.ScanDegradedRootNXDOMAIN},
		{"root resolver failure wins over enumeration failure", shared.ScanDegradedDNSFailures, true, 0, 0, shared.ScanDegradedDNSFailures},
		{"enumeration failed", "", true, 0, 0, shared.ScanDegradedSubdomainEnumFailed},
		{"exactly 20% is tolerated", "", false, 200, 40, ""},
		{"just over 20% degrades", "", false, 200, 41, shared.ScanDegradedDNSFailures},
		{"all failed but only 50 names is tolerated", "", false, 50, 50, ""},
		{"51 names, 11 failed degrades", "", false, 51, 11, shared.ScanDegradedDNSFailures},
		{"51 names, 10 failed is tolerated", "", false, 51, 10, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := degradedReason(tt.rootReason, tt.enumFailed, tt.names, tt.failures); got != tt.want {
				t.Errorf("degradedReason(%q, %v, %d, %d) = %q, want %q",
					tt.rootReason, tt.enumFailed, tt.names, tt.failures, got, tt.want)
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
	if !subdomainLookupsDegraded(len(names), failures) {
		t.Errorf("120 names with 30 failures (25%%) should be degraded")
	}
}
