package shared

import (
	"context"
	"fmt"
	"net"
)

// privateRanges contains all IP networks that must not be scanned.
// Covers RFC1918 private ranges, loopback, link-local (including AWS metadata),
// CGNAT, IPv6 loopback, and IPv6 unique-local (fc00::/7).
var privateRanges []*net.IPNet

func init() {
	// These CIDRs are the complete set of reserved/non-routable ranges that
	// an attacker could use to probe internal infrastructure via SSRF.
	reserved := []string{
		// IPv4 loopback (RFC 5735)
		"127.0.0.0/8",
		// IPv4 unspecified address
		"0.0.0.0/8",
		// RFC1918 private ranges
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// Link-local — includes 169.254.169.254 (AWS/GCP/Azure metadata)
		"169.254.0.0/16",
		// IETF protocol assignments
		"192.0.0.0/24",
		// TEST-NET ranges (RFC 5737) — documentation use, should not appear
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		// CGNAT (RFC 6598) — shared address space, reachable in some cloud environments
		"100.64.0.0/10",
		// Benchmarking (RFC 2544)
		"198.18.0.0/15",
		// Reserved (RFC 1112, broadcast)
		"240.0.0.0/4",
		// Multicast
		"224.0.0.0/4",
		// IPv6 loopback (::1/128)
		"::1/128",
		// IPv6 unspecified
		"::/128",
		// IPv6 link-local
		"fe80::/10",
		// IPv6 unique-local (fc00::/7) — equivalent of RFC1918
		"fc00::/7",
		// IPv6 multicast
		"ff00::/8",
		// Note: IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are handled by
		// normalising them to IPv4 via ip.To4() before the range checks,
		// so no explicit ::ffff:0:0/96 entry is needed here.
	}

	for _, cidr := range reserved {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// All CIDRs above are hard-coded and valid; panic on misconfiguration
			panic(fmt.Sprintf("shared: invalid private IP CIDR %q: %v", cidr, err))
		}
		privateRanges = append(privateRanges, network)
	}
}

// SSRFSafeDialContext returns a DialContext function that can be used directly
// as http.Transport.DialContext. It closes the DNS-rebinding TOCTOU gap that
// exists when an IP is validated before dialing but the OS performs a second
// DNS lookup at connection time.
//
// For each outbound connection the returned function will:
//  1. Parse the addr (host:port) produced by the HTTP stack.
//  2. If host is already a numeric IP, validate it with IsPrivateIP and dial.
//  3. If host is a name, resolve it (IPv4 + IPv6) via the default resolver.
//     If DNS fails the dial is rejected (fail-closed).
//  4. Validate every resolved IP with IsPrivateIP. If any IP is private the
//     dial is rejected — even if other addresses are public.
//  5. Dial directly to the first public IP by address (not hostname), so the
//     OS/Go runtime never performs a second lookup that could be rebound.
//
// The caller-supplied dialer controls timeouts and keep-alive settings.
func SSRFSafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf-guard: malformed address %q: %w", addr, err)
		}

		// Fast path — addr already contains a numeric IP (e.g. from a previous
		// redirect that the HTTP client resolved itself).
		if ip := net.ParseIP(host); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			for _, cidr := range privateRanges {
				if cidr.Contains(ip) {
					return nil, fmt.Errorf("ssrf-guard: refusing to connect to reserved IP %q", host)
				}
			}
			// Safe numeric IP — dial directly.
			return dialer.DialContext(ctx, network, addr)
		}

		// Slow path — resolve the hostname. Use "ip" to get both A and AAAA
		// records and validate all of them before connecting.
		resolver := net.DefaultResolver
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			// Fail closed: if we cannot resolve, we cannot verify safety.
			return nil, fmt.Errorf("ssrf-guard: DNS resolution failed for %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("ssrf-guard: DNS returned no addresses for %q", host)
		}

		// Validate every resolved address before we commit to any of them.
		for _, ip := range ips {
			normalised := ip
			if v4 := ip.To4(); v4 != nil {
				normalised = v4
			}
			for _, cidr := range privateRanges {
				if cidr.Contains(normalised) {
					return nil, fmt.Errorf("ssrf-guard: %q resolves to reserved IP %q", host, ip.String())
				}
			}
		}

		// Dial directly to the first validated IP — bypass the OS resolver so
		// a second lookup (which could be rebound) never occurs.
		firstIP := ips[0]
		safeAddr := net.JoinHostPort(firstIP.String(), port)
		return dialer.DialContext(ctx, network, safeAddr)
	}
}

// IsPrivateIP reports whether the given IP string falls within any reserved,
// loopback, link-local, or RFC1918 range.
//
// Returns false and an error if the string is not a valid IP address.
// Returns true if the IP is private/reserved (should be blocked).
// Returns false if the IP is a routable public address (safe to scan).
func IsPrivateIP(ipStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %q", ipStr)
	}

	// Normalise IPv4-in-IPv6 representation (e.g. "::ffff:192.168.1.1")
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}
