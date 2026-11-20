package domain_discovery

import (
	"context"
	"net"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/miekg/dns"
)

// recheckTimeout bounds one query to one public resolver.
const recheckTimeout = 3 * time.Second

// recheckResolversFromEnv returns the resolvers of DNS_RECHECK_RESOLVERS as host:port, or nil
// when the value is "off".
func recheckResolversFromEnv() []string { return shared.RecheckResolvers() }

// rootAnswer is what one public resolver said about a root domain.
type rootAnswer int

const (
	answerUnknown  rootAnswer = iota // no usable answer (error, SERVFAIL, REFUSED, ...)
	answerAddress                    // NOERROR with an A or AAAA record
	answerNoData                     // NOERROR, the name exists but has no A or AAAA record
	answerNXDomain                   // NXDOMAIN: the name does not exist
)

// rootNotFoundReason classifies a root domain that the local resolver reported as not found,
// by asking the public resolvers directly. It returns the degraded reason to record, or ""
// when the root exists without an address (an apex with no A/AAAA record is a fact, not a
// failure; its subdomains are still enumerated and checked).
//
//   - every answering resolver says NXDOMAIN: ScanDegradedRootNXDOMAIN
//   - any resolver returns an address: the local resolver failed, ScanDegradedDNSFailures
//   - every answering resolver says NOERROR without an address: ""
//   - no resolver answered, the answers disagree, or the check is off: ScanDegradedDNSFailures
func rootNotFoundReason(ctx context.Context, host string, servers []string) string {
	var nx, nodata int
	for _, server := range servers {
		switch answer, _ := queryRoot(ctx, host, server); answer {
		case answerAddress:
			return shared.ScanDegradedDNSFailures
		case answerNXDomain:
			nx++
		case answerNoData:
			nodata++
		}
	}
	switch {
	case nx > 0 && nodata == 0:
		return shared.ScanDegradedRootNXDOMAIN
	case nodata > 0 && nx == 0:
		return ""
	default:
		return shared.ScanDegradedDNSFailures
	}
}

// recheckName asks the public resolvers about a name that the local resolver reported as not
// found. It returns answerAddress with the addresses when any resolver has one (the local
// resolver failed), answerNXDomain when every resolver answered that the name has no address
// (NXDOMAIN or NODATA: as a host, it is gone), and answerUnknown otherwise (a resolver did not
// answer, or the check is off).
func recheckName(ctx context.Context, host string, servers []string) (rootAnswer, []net.IP) {
	gone := 0
	for _, server := range servers {
		switch answer, ips := queryRoot(ctx, host, server); answer {
		case answerAddress:
			return answerAddress, ips
		case answerNXDomain, answerNoData:
			gone++
		}
	}
	if len(servers) > 0 && gone == len(servers) {
		return answerNXDomain, nil
	}
	return answerUnknown, nil
}

// queryRoot asks one resolver for the A and AAAA records of host.
func queryRoot(ctx context.Context, host, server string) (rootAnswer, []net.IP) {
	a, ips := queryType(ctx, host, server, dns.TypeA)
	if a == answerAddress || a == answerNXDomain || a == answerUnknown {
		return a, ips
	}
	// A is NODATA: the name exists; it may still have an IPv6 address.
	aaaa, ips := queryType(ctx, host, server, dns.TypeAAAA)
	if aaaa == answerAddress || aaaa == answerNoData {
		return aaaa, ips
	}
	return answerUnknown, nil
}

// queryType sends one recursive query over UDP and repeats it over TCP when the UDP answer
// is truncated or lost. With answerAddress it returns the A or AAAA addresses.
func queryType(ctx context.Context, host, server string, qtype uint16) (rootAnswer, []net.IP) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true
	var resp *dns.Msg
	for _, network := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: network, Timeout: recheckTimeout}
		r, _, err := c.ExchangeContext(ctx, msg, server)
		if err == nil && r != nil && !r.Truncated {
			resp = r
			break
		}
	}
	if resp == nil {
		return answerUnknown, nil
	}
	switch resp.Rcode {
	case dns.RcodeNameError:
		return answerNXDomain, nil
	case dns.RcodeSuccess:
		var ips []net.IP
		for _, rr := range resp.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
			}
		}
		if len(ips) > 0 {
			return answerAddress, ips
		}
		return answerNoData, nil
	default:
		return answerUnknown, nil
	}
}
