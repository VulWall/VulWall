package shared

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestProbeErrorTreatsOnlyRefusedAsComplete(t *testing.T) {
	refused := &net.OpError{Op: "dial", Err: fmt.Errorf("connect: %w", syscall.ECONNREFUSED)}
	wrappedRefused := fmt.Errorf("failed to fetch headers from http://x: %w", refused)
	timeout := context.DeadlineExceeded

	cases := []struct {
		name string
		errs []error
		want bool // incomplete
	}{
		{"both answered", []error{nil, nil}, false},
		{"one refused", []error{wrappedRefused, nil}, false},
		{"both refused", []error{wrappedRefused, wrappedRefused}, false},
		{"one timed out", []error{nil, timeout}, true},
		{"refused and timed out", []error{wrappedRefused, timeout}, true},
		{"bad status", []error{errors.New("HTTP 503"), nil}, true},
	}
	for _, c := range cases {
		if got := ProbeError(c.errs...) != nil; got != c.want {
			t.Errorf("%s: incomplete = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsConnRefusedOnRealDial(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens now
	_, err = net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		t.Skip("port was reused")
	}
	if !IsConnRefused(fmt.Errorf("wrapped: %w", err)) {
		t.Fatalf("IsConnRefused(%v) = false, want true", err)
	}
}

func TestTargetCoverage(t *testing.T) {
	scanID := "scan-1"
	target := ScanTarget{Target: "a.example.com", DiscoveryID: "d1", OrgID: "org", ScanID: &scanID, TraceID: "tr"}
	keys := []FindingKey{{FindingType: "missing-hsts", Title: "Missing HSTS"}}

	ok := TargetCoverage("http-headers", target, keys, nil)
	if ok.Coverage == nil || ok.Coverage.Status != CoverageOK || len(ok.Coverage.Reported) != 1 {
		t.Fatalf("ok coverage = %+v", ok.Coverage)
	}
	if ok.Source != "http-headers" || ok.DiscoveryID != "d1" || ok.OrgID != "org" || *ok.ScanID != scanID {
		t.Fatalf("envelope = %+v, want source, discovery, org and scan of the target", ok)
	}

	failed := TargetCoverage("nuclei", target, keys, errors.New("exit 2"))
	if failed.Coverage.Status != CoverageError || failed.Coverage.Error == "" || failed.Coverage.Reported != nil {
		t.Fatalf("error coverage = %+v, want error status, message, no reported keys", failed.Coverage)
	}

	target.Unresolved = true
	unresolved := TargetCoverage("nuclei", target, nil, nil)
	if unresolved.Coverage.Status != CoverageError {
		t.Fatalf("unresolved host coverage = %+v, want error: a check of it proves nothing", unresolved.Coverage)
	}
}
