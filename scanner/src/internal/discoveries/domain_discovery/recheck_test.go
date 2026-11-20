package domain_discovery

import (
	"context"
	"net"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// startDNS runs a UDP DNS server on 127.0.0.1 that answers every query with handler and
// returns its address.
func startDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	started := make(chan struct{})
	srv := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func reply(rcode int, rrs ...string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		for _, s := range rrs {
			rr, err := dns.NewRR(s)
			if err != nil {
				panic(err)
			}
			if rr.Header().Rrtype == r.Question[0].Qtype || rr.Header().Rrtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	}
}

func TestRootNotFoundReason(t *testing.T) {
	t.Parallel()

	nx := startDNS(t, reply(dns.RcodeNameError))
	nodata := startDNS(t, reply(dns.RcodeSuccess))
	v4 := startDNS(t, reply(dns.RcodeSuccess, "dead.example. 60 IN A 203.0.113.7"))
	v6only := startDNS(t, reply(dns.RcodeSuccess, "dead.example. 60 IN AAAA 2001:db8::1"))
	cname := startDNS(t, reply(dns.RcodeSuccess, "dead.example. 60 IN CNAME x.example.", "x.example. 60 IN A 203.0.113.8"))
	refused := startDNS(t, reply(dns.RcodeRefused))
	servfail := startDNS(t, reply(dns.RcodeServerFailure))

	tests := []struct {
		name    string
		servers []string
		want    string
	}{
		{"all public resolvers say NXDOMAIN", []string{nx, nx}, shared.ScanDegradedRootNXDOMAIN},
		{"NXDOMAIN with one resolver refusing", []string{refused, nx}, shared.ScanDegradedRootNXDOMAIN},
		{"public resolver has an address: local failure", []string{nx, v4}, shared.ScanDegradedDNSFailures},
		{"IPv6-only address: local failure", []string{v6only}, shared.ScanDegradedDNSFailures},
		{"CNAME chain to an address: local failure", []string{cname}, shared.ScanDegradedDNSFailures},
		{"exists without address: not degraded", []string{nodata, nodata}, ""},
		{"NXDOMAIN and NODATA disagree", []string{nx, nodata}, shared.ScanDegradedDNSFailures},
		{"no usable answer", []string{refused, servfail}, shared.ScanDegradedDNSFailures},
		{"check disabled", nil, shared.ScanDegradedDNSFailures},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := rootNotFoundReason(context.Background(), "dead.example", tt.servers); got != tt.want {
				t.Errorf("rootNotFoundReason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecheckResolversFromEnv(t *testing.T) {
	tests := []struct {
		env  string
		want []string
	}{
		{"", []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{"off", nil},
		{"OFF", nil},
		{"9.9.9.9, 127.0.0.1:5353,", []string{"9.9.9.9:53", "127.0.0.1:5353"}},
	}
	for _, tt := range tests {
		t.Setenv(config.EnvDNSRecheckResolvers, tt.env)
		got := recheckResolversFromEnv()
		if len(got) != len(tt.want) {
			t.Fatalf("env %q: got %v, want %v", tt.env, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("env %q: got %v, want %v", tt.env, got, tt.want)
			}
		}
	}
}

// TestResolveIPs_RetriesOnlyLookupFailures: a clean NXDOMAIN for a subdomain is final (one
// lookup), the root still retries it, and a timeout is retried for both.
func TestResolveIPs_RetriesOnlyLookupFailures(t *testing.T) {
	t.Parallel()

	nxErr := &net.DNSError{Err: "no such host", IsNotFound: true}
	timeoutErr := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	tests := []struct {
		name          string
		err           error
		retryNotFound bool
		wantCalls     int
	}{
		{"subdomain NXDOMAIN is not retried", nxErr, false, 1},
		{"root NXDOMAIN is retried", nxErr, true, dnsRetryAttempts},
		{"subdomain timeout is retried", timeoutErr, false, dnsRetryAttempts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			s := &Service{logger: zap.NewNop(), lookupIP: func(context.Context, string, string) ([]net.IP, error) {
				calls++
				return nil, tt.err
			}}
			if _, err := s.resolveIPs(context.Background(), "x.example", tt.retryNotFound); err == nil {
				t.Fatal("resolveIPs returned no error")
			}
			if calls != tt.wantCalls {
				t.Errorf("lookups = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}
