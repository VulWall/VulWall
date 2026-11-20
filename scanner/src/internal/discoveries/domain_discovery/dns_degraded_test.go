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

	enumErr := errors.New("subfinder failed")
	tests := []struct {
		name       string
		rootReason string
		res        subdomainResult
		want       string
	}{
		{"clean run", "", subdomainResult{names: 200}, ""},
		{"root without address but existing is clean", "", subdomainResult{}, ""},
		{"root nxdomain", shared.ScanDegradedRootNXDOMAIN, subdomainResult{}, shared.ScanDegradedRootNXDOMAIN},
		{"root resolver failure wins over enumeration failure", shared.ScanDegradedDNSFailures, subdomainResult{enumErr: enumErr}, shared.ScanDegradedDNSFailures},
		{"publish failure", "", subdomainResult{names: 3, publishFailed: 1}, shared.ScanDegradedPublishFailed},
		{"enumeration failed", "", subdomainResult{enumErr: enumErr}, shared.ScanDegradedSubdomainEnumFailed},
		{"exactly 20% is tolerated", "", subdomainResult{names: 200, failures: 40}, ""},
		{"just over 20% degrades", "", subdomainResult{names: 200, failures: 41}, shared.ScanDegradedDNSFailures},
		{"small domain: no floor on the name count", "", subdomainResult{names: 2, failures: 1}, shared.ScanDegradedDNSFailures},
		{"any failed known name degrades", "", subdomainResult{names: 200, failures: 1, knownFailures: 1}, shared.ScanDegradedDNSFailures},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := degradedReason(tt.rootReason, tt.res); got != tt.want {
				t.Errorf("degradedReason(%q, %+v) = %q, want %q", tt.rootReason, tt.res, got, tt.want)
			}
		})
	}
}

func TestSubdomainNamesMergesKnownNames(t *testing.T) {
	t.Parallel()
	names, known := subdomainNames("example.com",
		[]string{"www", "api.example.com", "", "*", "www"},
		[]string{"API.example.com.", "old.example.com", "example.com", "other.org"})
	want := []string{"www.example.com", "api.example.com", "old.example.com"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if !known["api.example.com"] || !known["old.example.com"] || known["www.example.com"] || len(known) != 2 {
		t.Fatalf("known = %v, want api and old only (the root and foreign names are dropped)", known)
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
	if degradedReason("", subdomainResult{names: len(names), failures: failures}) != shared.ScanDegradedDNSFailures {
		t.Errorf("120 names with 30 failures (25%%) should be degraded")
	}
}
