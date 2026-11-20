package email_security_scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/miekg/dns"
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

// nsResolver answers NS lookups with fixed nameservers.
type nsResolver struct {
	fakeResolver
	ns []*net.NS
}

func (r nsResolver) LookupNS(context.Context, string) ([]*net.NS, error) { return r.ns, nil }

// TestZoneTransferReservedNameserverIsDefinite: a nameserver the SSRF guard refuses is
// skipped by design; it does not make the check incomplete.
func TestZoneTransferReservedNameserverIsDefinite(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "false")
	res, err := checkZoneTransfer(context.Background(), nsResolver{ns: []*net.NS{{Host: "127.0.0.1."}}}, "example.com")
	if err != nil || res != nil {
		t.Fatalf("checkZoneTransfer = %v, %v; want nil, nil", res, err)
	}
}

// TestZoneTransferNameserverLookupErrorIsIncomplete: a nameserver that was not looked up
// was not asked, so the check is incomplete.
func TestZoneTransferNameserverLookupErrorIsIncomplete(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "false")
	_, err := checkZoneTransfer(context.Background(), nsResolver{ns: []*net.NS{{Host: "ns1.vulwall-test.invalid."}}}, "example.com")
	if err == nil {
		t.Fatal("err = nil, want incomplete: the nameserver did not resolve")
	}
	if errors.Is(err, shared.ErrReservedIP) {
		t.Fatalf("err = %v, want a lookup error", err)
	}
}

func TestCountAXFRTimeoutBeforeAnyRecordIsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := make(chan *dns.Envelope, 1)
	ch <- &dns.Envelope{RR: []dns.RR{&dns.A{}}}
	close(ch)
	if n, err := countAXFR(ctx, ch); err == nil {
		t.Fatalf("countAXFR = %d, nil; want an error", n)
	}

	// No envelope at all, and the deadline passed.
	empty := make(chan *dns.Envelope)
	close(empty)
	if n, err := countAXFR(ctx, empty); err == nil {
		t.Fatalf("countAXFR(empty) = %d, nil; want an error", n)
	}
}

func TestCountAXFRRecordsBeforeTimeoutAreAnOpenTransfer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *dns.Envelope) // unbuffered: each send waits for the reader
	go func() {
		ch <- &dns.Envelope{RR: []dns.RR{&dns.A{}, &dns.A{}}}
		ch <- &dns.Envelope{RR: []dns.RR{&dns.A{}}} // taken only after the first was counted
		cancel()
		ch <- &dns.Envelope{RR: []dns.RR{&dns.A{}}} // seen after the deadline
		close(ch)
	}()
	n, err := countAXFR(ctx, ch)
	if err != nil || n < 2 {
		t.Fatalf("countAXFR = %d, %v; want >= 2, nil", n, err)
	}

	// A refused answer with no records is a definite no.
	refusedCh := make(chan *dns.Envelope, 1)
	refusedCh <- &dns.Envelope{Error: errors.New("dns: bad xfr rcode: 5")}
	close(refusedCh)
	if n, err := countAXFR(context.Background(), refusedCh); err != nil || n != 0 {
		t.Fatalf("countAXFR(refused) = %d, %v; want 0, nil", n, err)
	}
}
