package shared

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Public addresses: the guard refuses the documentation ranges (TEST-NET, 2001:db8::/32),
// so the fakes answer with real public literals.
const (
	publicV4  = "93.184.216.34"
	publicV6a = "2606:2800:220:1:248:1893:25c8:1946"
	publicV6b = "2606:2800:220:1:248:1893:25c8:1947"
)

// fakeNet is a resolver and a dialer for ssrfSafeDial. Dials to an address in conns
// succeed; dials to an address in hang block until their ctx ends; dials to an address in
// errs fail at once with its error; others fail with fail.
type fakeNet struct {
	answer  []string
	hang    map[string]bool
	conns   map[string]bool
	errs    map[string]error
	fail    error
	lookups atomic.Int32

	mu     sync.Mutex
	dialed []string
}

func (f *fakeNet) lookup(_ context.Context, _, _ string) ([]net.IP, error) {
	f.lookups.Add(1)
	ips := make([]net.IP, len(f.answer))
	for i, a := range f.answer {
		ips[i] = net.ParseIP(a)
	}
	return ips, nil
}

func (f *fakeNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	f.mu.Unlock()
	host, _, _ := net.SplitHostPort(addr)
	switch {
	case f.conns[host]:
		client, server := net.Pipe()
		server.Close()
		return client, nil
	case f.hang[host]:
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Net: network, Err: ctx.Err()}
	case f.errs[host] != nil:
		return nil, &net.OpError{Op: "dial", Net: network, Err: f.errs[host]}
	default:
		return nil, &net.OpError{Op: "dial", Net: network, Err: f.fail}
	}
}

func (f *fakeNet) dialedHosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	hosts := make([]string, len(f.dialed))
	for i, addr := range f.dialed {
		hosts[i], _, _ = net.SplitHostPort(addr)
	}
	return hosts
}

// The issue #51 case: the host resolves to an IPv6 address first, the IPv6 path is broken
// (network unreachable), and IPv4 works. The dial must connect over IPv4.
func TestSSRFSafeDial_BrokenIPv6FallsBackToIPv4(t *testing.T) {
	t.Parallel()
	f := &fakeNet{
		answer: []string{publicV6a, publicV4},
		conns:  map[string]bool{publicV4: true},
		fail:   syscall.ENETUNREACH,
	}
	conn, err := ssrfSafeDial(f.lookup, f.dial, 5*time.Second)(context.Background(), "tcp", "dual.example:443")
	if err != nil {
		t.Fatalf("dial: %v, want a connection over IPv4", err)
	}
	conn.Close()
	if got, want := f.dialedHosts(), []string{publicV6a, publicV4}; !slices.Equal(got, want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
	if n := f.lookups.Load(); n != 1 {
		t.Errorf("lookups = %d, want 1 (no second resolution)", n)
	}
}

// A blackholed IPv6 path hangs instead of failing. The IPv6 attempt gets only part of the
// budget, so IPv4 still connects and the whole call stays inside the timeout.
func TestSSRFSafeDial_BlackholedIPv6LeavesTimeForIPv4(t *testing.T) {
	t.Parallel()
	f := &fakeNet{
		answer: []string{publicV6a, publicV4},
		hang:   map[string]bool{publicV6a: true},
		conns:  map[string]bool{publicV4: true},
	}
	const budget = 4 * time.Second
	start := time.Now()
	conn, err := ssrfSafeDial(f.lookup, f.dial, budget)(context.Background(), "tcp", "dual.example:443")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial: %v, want a connection over IPv4", err)
	}
	conn.Close()
	if elapsed >= budget {
		t.Errorf("dial took %v, want less than the %v budget", elapsed, budget)
	}
	if got, want := f.dialedHosts(), []string{publicV6a, publicV4}; !slices.Equal(got, want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
}

func TestSSRFSafeDial_AllAddressesFail(t *testing.T) {
	t.Parallel()
	f := &fakeNet{answer: []string{publicV6a, publicV4}, fail: syscall.ECONNREFUSED}
	_, err := ssrfSafeDial(f.lookup, f.dial, 5*time.Second)(context.Background(), "tcp", "down.example:443")
	if err == nil {
		t.Fatal("dial succeeded, want an error")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("error %v does not wrap ECONNREFUSED", err)
	}
	if got, want := f.dialedHosts(), []string{publicV6a, publicV4}; !slices.Equal(got, want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
}

// With one address the dial error comes back as it is, so a timeout is still a net.Error
// whose Timeout() is true (a joined error would hide it).
func TestSSRFSafeDial_SingleAddressErrorUnchanged(t *testing.T) {
	t.Parallel()
	f := &fakeNet{answer: []string{publicV4}, hang: map[string]bool{publicV4: true}}
	_, err := ssrfSafeDial(f.lookup, f.dial, 50*time.Millisecond)(context.Background(), "tcp", "slow.example:443")
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("error %v, want a net.Error with Timeout() true", err)
	}
	if _, joined := err.(interface{ Unwrap() []error }); joined {
		t.Errorf("error %v is a joined error, want the single dial error", err)
	}
}

// A reserved address anywhere in the answer refuses the whole dial before any connection
// attempt, as before the fallback.
func TestSSRFSafeDial_PrivateAddressInSetRefused(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "false")
	f := &fakeNet{
		answer: []string{publicV4, "10.0.0.1", publicV6a},
		conns:  map[string]bool{publicV4: true, "10.0.0.1": true, publicV6a: true},
	}
	conn, err := ssrfSafeDial(f.lookup, f.dial, 5*time.Second)(context.Background(), "tcp", "mixed.example:443")
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded, want the SSRF guard to refuse it")
	}
	if !errors.Is(err, ErrReservedIP) {
		t.Errorf("error %v, want ErrReservedIP", err)
	}
	if got := f.dialedHosts(); len(got) != 0 {
		t.Errorf("dialed %v, want no dial", got)
	}
}

// Cancelling the caller's ctx during an attempt stops the dial: no further address is tried.
func TestSSRFSafeDial_CancelStopsAttempts(t *testing.T) {
	t.Parallel()
	f := &fakeNet{
		answer: []string{publicV6a, publicV4},
		hang:   map[string]bool{publicV6a: true},
		conns:  map[string]bool{publicV4: true},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for len(f.dialedHosts()) == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	conn, err := ssrfSafeDial(f.lookup, f.dial, 0)(ctx, "tcp", "dual.example:443")
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded after cancel, want an error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
	if got, want := f.dialedHosts(), []string{publicV6a}; !slices.Equal(got, want) {
		t.Errorf("dialed %v, want only %v", got, want)
	}
}

// The families alternate, so a host with several IPv6 addresses reaches IPv4 on the second
// attempt, and every dial goes to a resolved IP literal.
func TestSSRFSafeDial_InterleavesFamilies(t *testing.T) {
	t.Parallel()
	f := &fakeNet{answer: []string{publicV6a, publicV6b, publicV4}, fail: syscall.ENETUNREACH}
	_, err := ssrfSafeDial(f.lookup, f.dial, 0)(context.Background(), "tcp", "multi.example:80")
	if err == nil {
		t.Fatal("dial succeeded, want an error")
	}
	if got, want := f.dialedHosts(), []string{publicV6a, publicV4, publicV6b}; !slices.Equal(got, want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
}

func TestPartialDeadline(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cases := []struct {
		left      time.Duration
		addrsLeft int
		want      time.Duration
	}{
		{10 * time.Second, 2, 5 * time.Second}, // even split
		{5 * time.Second, 4, 2 * time.Second},  // floor of 2s
		{1 * time.Second, 3, 1 * time.Second},  // less than the floor left: all of it
		{3 * time.Second, 1, 3 * time.Second},  // last address: all that is left
	}
	for _, tc := range cases {
		if got := partialDeadline(now, now.Add(tc.left), tc.addrsLeft).Sub(now); got != tc.want {
			t.Errorf("partialDeadline(left %v, %d addrs) = %v, want %v", tc.left, tc.addrsLeft, got, tc.want)
		}
	}
}

// When every attempt times out, the error is still a net.Error whose Timeout() is true, as
// for a single address: callers such as url.Error.Timeout() type-assert it.
func TestSSRFSafeDial_AllTimeoutsIsTimeout(t *testing.T) {
	t.Parallel()
	f := &fakeNet{
		answer: []string{publicV6a, publicV4},
		hang:   map[string]bool{publicV6a: true, publicV4: true},
	}
	_, err := ssrfSafeDial(f.lookup, f.dial, 50*time.Millisecond)(context.Background(), "tcp", "slow.example:443")
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("error %v (%T), want a net.Error with Timeout() true", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v does not wrap context.DeadlineExceeded", err)
	}
}

// errTimeout is what net returns for a dial that ran out of time ("i/o timeout").
var errTimeout = os.ErrDeadlineExceeded

// A multi-address dial reads as refused (IsConnRefused, so "nothing listens") only when
// every attempt was refused or found its address family unusable, and at least one was
// refused. A timeout, a cancel or another error on any address leaves it not refused: that
// address may have a listener, so the check is incomplete.
func TestIsConnRefused_MultiAddressDial(t *testing.T) {
	t.Parallel()
	refused, unreach, noAddr := syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EADDRNOTAVAIL
	cases := []struct {
		name        string
		v6, v4      error
		wantRefused bool
	}{
		{"all refused", refused, refused, true},
		{"broken IPv6, closed IPv4 port (issue #51)", unreach, refused, true},
		{"IPv6 address not available, closed IPv4 port", noAddr, refused, true},
		{"no family usable, none refused", unreach, noAddr, false},
		{"timeout then refused", errTimeout, refused, false},
		{"refused then timeout", refused, errTimeout, false},
		{"refused then reset", refused, syscall.ECONNRESET, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeNet{
				answer: []string{publicV6a, publicV4},
				errs:   map[string]error{publicV6a: tc.v6, publicV4: tc.v4},
			}
			_, err := ssrfSafeDial(f.lookup, f.dial, 5*time.Second)(context.Background(), "tcp", "dual.example:80")
			if err == nil {
				t.Fatal("dial succeeded, want an error")
			}
			if got := IsConnRefused(err); got != tc.wantRefused {
				t.Errorf("IsConnRefused(%v) = %v, want %v", err, got, tc.wantRefused)
			}
		})
	}
}

// Cancelling the dial after a refusal is not a refusal: the other address was never tried.
func TestIsConnRefused_RefusedThenCancelled(t *testing.T) {
	t.Parallel()
	f := &fakeNet{
		answer: []string{publicV6a, publicV4},
		errs:   map[string]error{publicV6a: syscall.ECONNREFUSED},
		hang:   map[string]bool{publicV4: true},
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for len(f.dialedHosts()) < 2 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	_, err := ssrfSafeDial(f.lookup, f.dial, 0)(ctx, "tcp", "dual.example:80")
	if IsConnRefused(err) {
		t.Errorf("IsConnRefused(%v) = true, want false", err)
	}
}

// The error of a multi-address dial reaches ProbeError through http.Client (url.Error
// around it): a timeout next to a refusal makes the check incomplete; refusals only, next
// to a protocol that answered, do not.
func TestProbeError_MultiAddressDialThroughHTTPClient(t *testing.T) {
	t.Parallel()
	get := func(errs map[string]error) error {
		f := &fakeNet{answer: []string{publicV6a, publicV4}, errs: errs}
		client := &http.Client{Transport: &http.Transport{
			DialContext: ssrfSafeDial(f.lookup, f.dial, 5*time.Second),
		}}
		resp, err := client.Get("http://dual.example/")
		if err == nil {
			resp.Body.Close()
			t.Fatal("GET succeeded, want a dial error")
		}
		return err
	}

	mixed := get(map[string]error{publicV6a: errTimeout, publicV4: syscall.ECONNREFUSED})
	if err := ProbeError(mixed, nil); err == nil {
		t.Errorf("ProbeError(timeout+refused, answered) = nil, want the check incomplete")
	}

	allRefused := get(map[string]error{publicV6a: syscall.ECONNREFUSED, publicV4: syscall.ECONNREFUSED})
	if err := ProbeError(allRefused, nil); err != nil {
		t.Errorf("ProbeError(all refused, answered) = %v, want nil", err)
	}

	issue51 := get(map[string]error{publicV6a: syscall.ENETUNREACH, publicV4: syscall.ECONNREFUSED})
	if err := ProbeError(issue51, nil); err != nil {
		t.Errorf("ProbeError(unreachable+refused, answered) = %v, want nil", err)
	}
}
