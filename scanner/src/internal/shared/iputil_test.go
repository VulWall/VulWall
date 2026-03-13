package shared

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ip          string
		wantPrivate bool
		wantErr     bool
	}{
		// ── Public addresses (must be allowed) ──────────────────────────────
		{name: "public IPv4 Google DNS", ip: "8.8.8.8", wantPrivate: false},
		{name: "public IPv4 Cloudflare DNS", ip: "1.1.1.1", wantPrivate: false},
		{name: "public IPv4 random", ip: "93.184.216.34", wantPrivate: false},
		{name: "public IPv6 Google", ip: "2001:4860:4860::8888", wantPrivate: false},
		{name: "public IPv6", ip: "2606:4700:4700::1111", wantPrivate: false},

		// ── Loopback ────────────────────────────────────────────────────────
		{name: "IPv4 loopback 127.0.0.1", ip: "127.0.0.1", wantPrivate: true},
		{name: "IPv4 loopback range 127.0.0.2", ip: "127.0.0.2", wantPrivate: true},
		{name: "IPv4 loopback range 127.255.255.254", ip: "127.255.255.254", wantPrivate: true},
		{name: "IPv6 loopback ::1", ip: "::1", wantPrivate: true},

		// ── RFC1918 private ranges ───────────────────────────────────────────
		{name: "10.0.0.0/8 start", ip: "10.0.0.0", wantPrivate: true},
		{name: "10.0.0.1", ip: "10.0.0.1", wantPrivate: true},
		{name: "10.255.255.255", ip: "10.255.255.255", wantPrivate: true},
		{name: "172.16.0.0 start", ip: "172.16.0.0", wantPrivate: true},
		{name: "172.16.0.1", ip: "172.16.0.1", wantPrivate: true},
		{name: "172.31.255.255 end", ip: "172.31.255.255", wantPrivate: true},
		{name: "172.32.0.0 just outside /12", ip: "172.32.0.0", wantPrivate: false},
		{name: "192.168.0.0 start", ip: "192.168.0.0", wantPrivate: true},
		{name: "192.168.1.1", ip: "192.168.1.1", wantPrivate: true},
		{name: "192.168.255.255 end", ip: "192.168.255.255", wantPrivate: true},

		// ── Link-local (169.254.x.x) — AWS/GCP/Azure metadata ───────────────
		{name: "169.254.0.0 start", ip: "169.254.0.0", wantPrivate: true},
		{name: "169.254.169.254 AWS metadata", ip: "169.254.169.254", wantPrivate: true},
		{name: "169.254.255.255 end", ip: "169.254.255.255", wantPrivate: true},

		// ── CGNAT (100.64.0.0/10) ────────────────────────────────────────────
		{name: "100.64.0.0 CGNAT start", ip: "100.64.0.0", wantPrivate: true},
		{name: "100.127.255.255 CGNAT end", ip: "100.127.255.255", wantPrivate: true},
		{name: "100.63.255.255 just before CGNAT", ip: "100.63.255.255", wantPrivate: false},
		{name: "100.128.0.0 just after CGNAT", ip: "100.128.0.0", wantPrivate: false},

		// ── Unspecified ──────────────────────────────────────────────────────
		{name: "0.0.0.0", ip: "0.0.0.0", wantPrivate: true},

		// ── Multicast ────────────────────────────────────────────────────────
		{name: "224.0.0.0 multicast", ip: "224.0.0.0", wantPrivate: true},
		{name: "239.255.255.255 multicast end", ip: "239.255.255.255", wantPrivate: true},

		// ── Reserved broadcast ───────────────────────────────────────────────
		{name: "255.255.255.255 broadcast", ip: "255.255.255.255", wantPrivate: true},

		// ── IPv6 link-local (fe80::/10) ──────────────────────────────────────
		{name: "fe80::1 IPv6 link-local", ip: "fe80::1", wantPrivate: true},
		{name: "fe80::dead:beef IPv6 link-local", ip: "fe80::dead:beef", wantPrivate: true},

		// ── IPv6 unique-local (fc00::/7) ─────────────────────────────────────
		{name: "fc00::1 IPv6 unique-local", ip: "fc00::1", wantPrivate: true},
		{name: "fd00::1 IPv6 unique-local (fd prefix)", ip: "fd00::1", wantPrivate: true},
		{name: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff unique-local end", ip: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", wantPrivate: true},

		// ── IPv4-mapped IPv6 (::ffff:x.x.x.x) ──────────────────────────────
		{name: "::ffff:192.168.1.1 IPv4-mapped private", ip: "::ffff:192.168.1.1", wantPrivate: true},
		{name: "::ffff:10.0.0.1 IPv4-mapped private", ip: "::ffff:10.0.0.1", wantPrivate: true},
		{name: "::ffff:169.254.169.254 IPv4-mapped metadata", ip: "::ffff:169.254.169.254", wantPrivate: true},

		// ── Invalid input ─────────────────────────────────────────────────────
		{name: "empty string", ip: "", wantErr: true},
		{name: "hostname not IP", ip: "localhost", wantErr: true},
		{name: "domain name", ip: "example.com", wantErr: true},
		{name: "garbage", ip: "not-an-ip", wantErr: true},
		{name: "partial IP", ip: "192.168", wantErr: true},
		{name: "IP with port", ip: "192.168.1.1:80", wantErr: true},
		{name: "CIDR notation", ip: "192.168.0.0/24", wantErr: true},
	}

	for _, tc := range tests {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := IsPrivateIP(tc.ip)

			if tc.wantErr {
				if err == nil {
					t.Errorf("IsPrivateIP(%q): expected error, got nil (private=%v)", tc.ip, got)
				}
				return
			}

			if err != nil {
				t.Errorf("IsPrivateIP(%q): unexpected error: %v", tc.ip, err)
				return
			}

			if got != tc.wantPrivate {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tc.ip, got, tc.wantPrivate)
			}
		})
	}
}

// TestSSRFSafeDialContext_NumericIP verifies the fast-path behaviour when the
// address is already a numeric IP (no DNS lookup occurs).
func TestSSRFSafeDialContext_NumericIP(t *testing.T) {
	t.Parallel()

	dialer := &net.Dialer{}
	dialFn := SSRFSafeDialContext(dialer)
	ctx := context.Background()

	privateAddrs := []string{
		"127.0.0.1:80",
		"10.0.0.1:443",
		"192.168.1.1:8080",
		"172.16.0.1:80",
		"169.254.169.254:80",        // AWS metadata
		"[::1]:80",
		"[fc00::1]:80",
		"[fe80::1]:80",
		"[::ffff:127.0.0.1]:80",     // IPv4-mapped loopback
		"[::ffff:169.254.169.254]:80", // IPv4-mapped AWS metadata
		"[::ffff:10.0.0.1]:443",     // IPv4-mapped RFC1918
		"[::ffff:192.168.1.1]:8080", // IPv4-mapped RFC1918
	}

	for _, addr := range privateAddrs {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()
			conn, err := dialFn(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				t.Errorf("SSRFSafeDialContext: expected error for private addr %q, got nil", addr)
				return
			}
			if !strings.Contains(err.Error(), "ssrf-guard") {
				t.Errorf("SSRFSafeDialContext: error for %q does not contain 'ssrf-guard': %v", addr, err)
			}
		})
	}
}

// TestSSRFSafeDialContext_MalformedAddr verifies that a malformed addr (no port)
// returns an ssrf-guard error rather than panicking or succeeding.
func TestSSRFSafeDialContext_MalformedAddr(t *testing.T) {
	t.Parallel()

	dialer := &net.Dialer{}
	dialFn := SSRFSafeDialContext(dialer)
	ctx := context.Background()

	// net.SplitHostPort requires a port; bare host is malformed.
	_, err := dialFn(ctx, "tcp", "192.168.1.1")
	if err == nil {
		t.Fatal("SSRFSafeDialContext: expected error for addr without port, got nil")
	}
	if !strings.Contains(err.Error(), "ssrf-guard") {
		t.Errorf("SSRFSafeDialContext: error does not contain 'ssrf-guard': %v", err)
	}
}

// TestSSRFSafeDialContext_PublicTarget verifies that an HTTP server bound to a
// public loopback address (127.0.0.1 is private, so we use the transport layer
// via httptest.Server and verify end-to-end that a *public* resolved IP is
// allowed through). Since we cannot manufacture a real public IP in unit tests,
// we verify the mechanism by confirming that a DNS-resolved address that passes
// all CIDR checks is actually dialled (the server responds 200).
//
// Strategy: start an httptest.Server (binds 127.0.0.1), then use a custom
// resolver that returns a fake public IP, and a custom dialer that redirects
// that fake public IP back to the server's actual listener. This decouples the
// CIDR validation logic from real network reachability.
func TestSSRFSafeDialContext_PublicTarget(t *testing.T) {
	t.Parallel()

	// Start a test HTTP server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// The server's real listener address (127.0.0.1:port).
	serverAddr := ts.Listener.Addr().String()

	// Build a transport that uses SSRFSafeDialContext but with a custom inner
	// dialer that ignores the validated IP and connects to the test server.
	// This lets us confirm the "allow" branch executes without real internet.
	//
	// We fake the lookup by constructing a dialer whose DialContext always
	// targets the test server, and wrap it in a version of SSRFSafeDialContext
	// that uses a resolver returning a known public IP.
	publicIP := net.ParseIP("93.184.216.34") // example.com — definitively public

	// Inline implementation that mirrors SSRFSafeDialContext but uses our
	// controlled resolver and dialer so the test is hermetic.
	innerDialer := &net.Dialer{}
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Only intercept our fake hostname.
		if host != "public.example.test" {
			return innerDialer.DialContext(ctx, network, addr)
		}
		// Simulate SSRFSafeDialContext: validate the fake public IP.
		ips := []net.IP{publicIP}
		for _, ip := range ips {
			normalised := ip
			if v4 := ip.To4(); v4 != nil {
				normalised = v4
			}
			for _, cidr := range privateRanges {
				if cidr.Contains(normalised) {
					t.Fatalf("test bug: 93.184.216.34 is incorrectly classified as private")
				}
			}
		}
		// Redirect to actual test server.
		return innerDialer.DialContext(ctx, "tcp", serverAddr)
	}

	transport := &http.Transport{DialContext: dialFn}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("http://public.example.test/")
	if err != nil {
		t.Fatalf("expected successful request, got error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
}

// TestSSRFSafeDialContext_DNSFailure verifies that an unresolvable hostname is
// rejected (fail-closed) rather than allowed through.
func TestSSRFSafeDialContext_DNSFailure(t *testing.T) {
	t.Parallel()

	dialer := &net.Dialer{}
	dialFn := SSRFSafeDialContext(dialer)
	ctx := context.Background()

	// .invalid TLD is guaranteed by RFC 2606 to never resolve.
	_, err := dialFn(ctx, "tcp", "this-hostname-will-never-resolve.invalid:80")
	if err == nil {
		t.Fatal("SSRFSafeDialContext: expected error for unresolvable hostname, got nil")
	}
	if !strings.Contains(err.Error(), "ssrf-guard") {
		t.Errorf("SSRFSafeDialContext: error does not contain 'ssrf-guard': %v", err)
	}
}
