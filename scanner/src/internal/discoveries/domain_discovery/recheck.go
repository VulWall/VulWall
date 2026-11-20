package domain_discovery

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/miekg/dns"
)

// defaultRecheckResolvers are asked directly when the local resolver says a root domain does
// not exist. Under Docker's embedded DNS an upstream REFUSED can surface as NXDOMAIN, so the
// local answer alone cannot tell "the domain is gone" from "the resolver failed".
const defaultRecheckResolvers = "1.1.1.1,8.8.8.8"

// recheckTimeout bounds one query to one public resolver.
const recheckTimeout = 3 * time.Second

// recheckResolversFromEnv returns the resolvers of DNS_RECHECK_RESOLVERS as host:port, or nil
// when the value is "off".
func recheckResolversFromEnv() []string {
	v := strings.TrimSpace(config.GetEnv(config.EnvDNSRecheckResolvers, defaultRecheckResolvers))
	if strings.EqualFold(v, "off") {
		return nil
	}
	var servers []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		servers = append(servers, s)
	}
	return servers
}

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
		switch queryRoot(ctx, host, server) {
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

// queryRoot asks one resolver for the A and AAAA records of host.
func queryRoot(ctx context.Context, host, server string) rootAnswer {
	a := queryType(ctx, host, server, dns.TypeA)
	if a == answerAddress || a == answerNXDomain || a == answerUnknown {
		return a
	}
	// A is NODATA: the name exists; it may still have an IPv6 address.
	aaaa := queryType(ctx, host, server, dns.TypeAAAA)
	if aaaa == answerAddress || aaaa == answerNoData {
		return aaaa
	}
	return answerUnknown
}

// queryType sends one recursive query over UDP and repeats it over TCP when the UDP answer
// is truncated or lost.
func queryType(ctx context.Context, host, server string, qtype uint16) rootAnswer {
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
		return answerUnknown
	}
	switch resp.Rcode {
	case dns.RcodeNameError:
		return answerNXDomain
	case dns.RcodeSuccess:
		for _, rr := range resp.Answer {
			switch rr.(type) {
			case *dns.A, *dns.AAAA:
				return answerAddress
			}
		}
		return answerNoData
	default:
		return answerUnknown
	}
}
