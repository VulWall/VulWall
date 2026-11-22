package shared

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

// privateRanges contains all IP networks that must not be scanned.
// Covers RFC1918 private ranges, loopback, link-local (including AWS metadata),
// CGNAT, IPv6 loopback, and IPv6 unique-local (fc00::/7). IPv6 addresses that
// embed an IPv4 address are also checked by that IPv4 address (isReservedIP).
var privateRanges []*net.IPNet

// IPv6 ranges that embed an IPv4 address the traffic goes to (embeddedIPv4).
var (
	nat64WellKnown = mustParseCIDR("64:ff9b::/96") // RFC 6052: IPv4 in the last 32 bits
	sixToFour      = mustParseCIDR("2002::/16")    // RFC 3056: IPv4 in bits 16-47
	teredo         = mustParseCIDR("2001::/32")    // RFC 4380: server in bits 32-63, client inverted in the last 32
)

func mustParseCIDR(cidr string) *net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(fmt.Sprintf("shared: invalid CIDR %q: %v", cidr, err))
	}
	return network
}

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
		// IPv4-compatible IPv6 (RFC 4291, deprecated), e.g. ::7f00:1; some stacks
		// route it to the embedded IPv4 address. Covers ::/128 and ::1/128 too.
		"::/96",
		// IPv6 discard-only (RFC 6666)
		"100::/64",
		// IPv6 documentation (RFC 3849)
		"2001:db8::/32",
		// Local-use NAT64 (RFC 8215). The IPv4 position depends on the prefix
		// length the translator uses (RFC 6052: /48 to /96), which the address does
		// not show, so no reading of it is safe. The well-known prefix 64:ff9b::/96
		// is decoded instead (embeddedIPv4).
		"64:ff9b:1::/48",
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

// PrivateTargetsAllowed reports whether ALLOW_PRIVATE_TARGETS is enabled.
// Default false: private, loopback and other reserved addresses are never
// scanned or dialed. Read on each call so tests can toggle it with t.Setenv.
func PrivateTargetsAllowed() bool {
	return config.GetEnvBool(config.EnvAllowPrivateTargets, false)
}

// ErrReservedIP marks an address that the SSRF guard refuses: a definite answer that the
// target must not be dialed, not a failed lookup.
var ErrReservedIP = errors.New("ssrf-guard: refusing reserved IP")

// CheckPublicIPs returns an error if any address in ips is in a reserved
// range, unless PrivateTargetsAllowed. Every address is checked: a host with
// one public and one private answer is rejected, because a later lookup may
// return the private one.
func CheckPublicIPs(ips []net.IP) error {
	if PrivateTargetsAllowed() {
		return nil
	}
	for _, ip := range ips {
		if isReservedIP(ip) {
			return fmt.Errorf("%w %q", ErrReservedIP, ip.String())
		}
	}
	return nil
}

// isReservedIP reports whether ip is in a reserved range, or is an IPv6 address
// that embeds (NAT64, 6to4, Teredo) an IPv4 address in one. IPv4-mapped IPv6
// (::ffff:a.b.c.d) is checked as its IPv4 address.
func isReservedIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return inPrivateRanges(v4)
	}
	if inPrivateRanges(ip) {
		return true
	}
	for _, v4 := range embeddedIPv4(ip) {
		if inPrivateRanges(v4) {
			return true
		}
	}
	return false
}

func inPrivateRanges(ip net.IP) bool {
	for _, cidr := range privateRanges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// embeddedIPv4 returns the IPv4 addresses that an IPv6 address in a translation
// or tunnel range sends traffic to: NAT64 well-known prefix, 6to4, and Teredo
// (both the server and the client). These ranges are not refused as a whole: an
// IPv6-only network with DNS64 reaches public IPv4 hosts through them.
func embeddedIPv4(ip net.IP) []net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	switch {
	case nat64WellKnown.Contains(ip):
		return []net.IP{net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()}
	case sixToFour.Contains(ip):
		return []net.IP{net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()}
	case teredo.Contains(ip):
		return []net.IP{
			net.IPv4(ip[4], ip[5], ip[6], ip[7]).To4(),
			net.IPv4(^ip[12], ^ip[13], ^ip[14], ^ip[15]).To4(),
		}
	}
	return nil
}

// ResolvePublicIPs resolves host (A and AAAA) and validates every answer with
// CheckPublicIPs. It fails closed: a DNS error or an empty answer is an error.
// A numeric host is validated without a lookup.
func ResolvePublicIPs(ctx context.Context, host string) ([]net.IP, error) {
	return resolvePublicIPs(ctx, net.DefaultResolver.LookupIP, host)
}

// lookupIPFunc and dialFunc are the network operations of SSRFSafeDialContext; tests pass
// fakes for them.
type (
	lookupIPFunc func(ctx context.Context, network, host string) ([]net.IP, error)
	dialFunc     func(ctx context.Context, network, addr string) (net.Conn, error)
)

func resolvePublicIPs(ctx context.Context, lookup lookupIPFunc, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		ips := []net.IP{ip}
		return ips, CheckPublicIPs(ips)
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("ssrf-guard: DNS resolution failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("ssrf-guard: DNS returned no addresses for %q", host)
	}
	if err := CheckPublicIPs(ips); err != nil {
		return nil, fmt.Errorf("%w (resolved from %q)", err, host)
	}
	return ips, nil
}

// SSRFSafeDialContext returns a DialContext function that can be used directly
// as http.Transport.DialContext. It closes the DNS-rebinding TOCTOU gap that
// exists when an IP is validated before dialing but the OS performs a second
// DNS lookup at connection time.
//
// For each outbound connection the returned function will:
//  1. Parse the addr (host:port) produced by the HTTP stack.
//  2. Resolve and validate the host with ResolvePublicIPs (numeric hosts are
//     validated without a lookup; DNS failure is rejected, fail-closed; any
//     reserved answer rejects the dial, even if other answers are public).
//  3. Dial the validated IPs by address (not hostname), one after the other
//     until one connects, so the OS/Go runtime never performs a second lookup
//     that could be rebound. See dialEach for the order and the time budget.
//
// ALLOW_PRIVATE_TARGETS=true disables the reserved-range check but keeps the
// single-resolution dial.
//
// The caller-supplied dialer controls keep-alive settings. Its Timeout bounds the
// whole call, all addresses together, as it does for a net.Dialer given a host name.
func SSRFSafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrfSafeDial(net.DefaultResolver.LookupIP, dialer.DialContext, dialer.Timeout)
}

func ssrfSafeDial(lookup lookupIPFunc, dial dialFunc, timeout time.Duration) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf-guard: malformed address %q: %w", addr, err)
		}

		ips, err := resolvePublicIPs(ctx, lookup, host)
		if err != nil {
			return nil, err
		}

		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return dialEach(ctx, dial, network, interleaveFamilies(ips), port)
	}
}

// dialEach dials ips (validated by the caller) in order and returns the first connection.
// A dual-stack host whose IPv6 path is broken still connects over IPv4.
//
// The attempts share the ctx deadline: each one gets the remaining time divided by the
// addresses left, but at least 2 seconds, like net.Dialer with a host name (net's
// partialDeadline). So a first address that hangs takes half of a two-address budget, not
// all of it, and the call never takes longer than the deadline. Sequential attempts keep
// the code simple; Happy Eyeballs (RFC 8305) would connect faster on a broken IPv6 path, but
// the scanners are batch jobs and do not need that.
//
// The error is the dial error itself when one address was tried; otherwise a dialErrors
// with the error of every attempt (see IsConnRefused for when that reads as refused).
func dialEach(ctx context.Context, dial dialFunc, network string, ips []net.IP, port string) (net.Conn, error) {
	var errs []error
	for i, ip := range ips {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			attemptCtx, cancel = context.WithDeadline(ctx, partialDeadline(time.Now(), deadline, len(ips)-i))
		}
		conn, err := dial(attemptCtx, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 1 {
		return nil, errs[0]
	}
	return nil, dialErrors(errs)
}

// dialErrors is the error of a dial in which every address failed. It is a net.Error, like
// the error of a single dial, so callers that check Timeout() keep working: it is a timeout
// when every attempt timed out.
type dialErrors []error

func (e dialErrors) Error() string   { return errors.Join(e...).Error() }
func (e dialErrors) Unwrap() []error { return e }
func (e dialErrors) Temporary() bool { return e.Timeout() }

// allRefused reports whether the dial is a definite "nothing listens": every attempt was
// refused or found its address family unusable (no route, no source address: a broken
// IPv6 path), and at least one was refused. A timeout, a cancel or any other error leaves
// the answer open, because that address may have a listener.
func (e dialErrors) allRefused() bool {
	refused := false
	for _, err := range e {
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			refused = true
		case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL):
		default:
			return false
		}
	}
	return refused
}

func (e dialErrors) Timeout() bool {
	for _, err := range e {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return false
		}
	}
	return true
}

// minAttemptTime is the shortest time dialEach gives one address while more time is left,
// as net's saneMinimum.
const minAttemptTime = 2 * time.Second

// partialDeadline returns the deadline of one attempt when addrsLeft addresses (this one
// included) share the time until deadline.
func partialDeadline(now, deadline time.Time, addrsLeft int) time.Time {
	left := deadline.Sub(now)
	share := left / time.Duration(addrsLeft)
	if share < minAttemptTime {
		share = min(minAttemptTime, left)
	}
	return now.Add(share)
}

// interleaveFamilies orders ips so that the address families alternate, starting with the
// family of the first address and keeping the resolver order within a family (RFC 8305
// section 4). A host with several IPv6 addresses on a broken IPv6 path then reaches IPv4 on
// the second attempt, before the budget runs out.
func interleaveFamilies(ips []net.IP) []net.IP {
	var first, other []net.IP
	isV4 := ips[0].To4() != nil
	for _, ip := range ips {
		if (ip.To4() != nil) == isV4 {
			first = append(first, ip)
		} else {
			other = append(other, ip)
		}
	}
	out := make([]net.IP, 0, len(ips))
	for i := 0; i < len(first) || i < len(other); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(other) {
			out = append(out, other[i])
		}
	}
	return out
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

	return isReservedIP(ip), nil
}
