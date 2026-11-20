package email_security_scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/miekg/dns"
)

// Common DKIM selectors to check
var dkimSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "dkim",
	"s1", "s2", "mail", "dkim1", "dkim2", "mx", "smtp", "email",
}

// isDNSNotFound checks if the error is a DNS NXDOMAIN error (record genuinely doesn't exist).
// Returns true only for NXDOMAIN; returns false for timeouts, SERVFAIL, and other transient errors.
func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// checkSPF performs SPF record validation for a domain
func checkSPF(ctx context.Context, resolver dnsResolver, domain string) ([]EmailCheckResult, error) {
	var results []EmailCheckResult

	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		// Only report missing records when the DNS answer is "not found". A transient
		// error (timeout, SERVFAIL) makes the check incomplete: it is returned.
		if isDNSNotFound(err) {
			results = append(results, EmailCheckResult{
				FindingType: "missing-spf",
				Severity:    shared.SeverityMedium,
				Title:       "Missing SPF Record",
				Description: "No SPF (Sender Policy Framework) record was found for this domain. Without SPF, attackers can send emails that appear to come from this domain, enabling phishing and spam campaigns. SPF helps receiving mail servers verify that incoming mail from a domain comes from an authorized IP address.",
				References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
			})
			return results, nil
		}
		return nil, fmt.Errorf("SPF lookup: %w", err)
	}

	// Find SPF record among TXT records
	var spfRecord string
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		results = append(results, EmailCheckResult{
			FindingType: "missing-spf",
			Severity:    shared.SeverityMedium,
			Title:       "Missing SPF Record",
			Description: "No SPF (Sender Policy Framework) record was found for this domain. Without SPF, attackers can send emails that appear to come from this domain, enabling phishing and spam campaigns. SPF helps receiving mail servers verify that incoming mail from a domain comes from an authorized IP address.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
		})
		return results, nil
	}

	lower := strings.ToLower(strings.TrimSpace(spfRecord))

	// Check for +all (allows all senders)
	if strings.HasSuffix(lower, "+all") {
		results = append(results, EmailCheckResult{
			FindingType: "spf-allows-all",
			Severity:    shared.SeverityHigh,
			Title:       "SPF Record Allows All Senders",
			Description: "The SPF record ends with '+all', which explicitly authorizes any server to send email on behalf of this domain. This completely negates the purpose of SPF and allows unrestricted email spoofing. The mechanism should be changed to '-all' (hard fail) to reject unauthorized senders.",
			Value:       spfRecord,
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208#section-5.1"},
		})
	}

	// Check for ~all (soft fail — not enforcing)
	if strings.HasSuffix(lower, "~all") {
		results = append(results, EmailCheckResult{
			FindingType: "spf-softfail-all",
			Severity:    shared.SeverityLow,
			Title:       "SPF Record Uses Soft Fail",
			Description: "The SPF record uses '~all' (soft fail) instead of '-all' (hard fail). While soft fail marks unauthorized emails as suspicious, it does not instruct receiving servers to reject them outright. For stronger protection against email spoofing, consider upgrading to '-all' which causes unauthorized emails to be rejected.",
			Value:       spfRecord,
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208#section-8.4"},
		})
	}

	return results, nil
}

// checkDMARC performs DMARC record validation for a domain
func checkDMARC(ctx context.Context, resolver dnsResolver, domain string) ([]EmailCheckResult, error) {
	var results []EmailCheckResult

	dmarcDomain := "_dmarc." + domain
	records, err := resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		// Only report missing records when the DNS answer is "not found". A transient
		// error (timeout, SERVFAIL) makes the check incomplete: it is returned.
		if isDNSNotFound(err) {
			results = append(results, EmailCheckResult{
				FindingType: "missing-dmarc",
				Severity:    shared.SeverityMedium,
				Title:       "Missing DMARC Record",
				Description: "No DMARC (Domain-based Message Authentication, Reporting & Conformance) record was found at _dmarc." + domain + ". DMARC builds on SPF and DKIM to provide domain-level email authentication. Without DMARC, there is no policy instructing receiving servers how to handle emails that fail authentication checks, leaving the domain vulnerable to spoofing.",
				References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
			})
			return results, nil
		}
		return nil, fmt.Errorf("DMARC lookup: %w", err)
	}

	// Find DMARC record
	var dmarcRecord string
	for _, record := range records {
		if strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		results = append(results, EmailCheckResult{
			FindingType: "missing-dmarc",
			Severity:    shared.SeverityMedium,
			Title:       "Missing DMARC Record",
			Description: "No DMARC (Domain-based Message Authentication, Reporting & Conformance) record was found at _dmarc." + domain + ". DMARC builds on SPF and DKIM to provide domain-level email authentication. Without DMARC, there is no policy instructing receiving servers how to handle emails that fail authentication checks, leaving the domain vulnerable to spoofing.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
		})
		return results, nil
	}

	lower := strings.ToLower(dmarcRecord)

	// Check for p=none (monitoring only, no enforcement)
	if containsTag(lower, "p", "none") {
		results = append(results, EmailCheckResult{
			FindingType: "dmarc-policy-none",
			Severity:    shared.SeverityMedium,
			Title:       "DMARC Policy Set to None",
			Description: "The DMARC policy is set to 'none', which only monitors email authentication failures without taking action. Emails that fail SPF/DKIM checks are still delivered normally. While 'p=none' is useful for initial deployment and gathering reports, it should be upgraded to 'p=quarantine' or 'p=reject' to actively protect against email spoofing.",
			Value:       dmarcRecord,
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"},
		})
	}

	// Check for missing rua (aggregate reports)
	if !strings.Contains(lower, "rua=") {
		results = append(results, EmailCheckResult{
			FindingType: "dmarc-no-rua",
			Severity:    shared.SeverityLow,
			Title:       "DMARC Missing Aggregate Reports",
			Description: "The DMARC record does not include an 'rua' tag for aggregate reports. Without aggregate reporting, the domain owner has no visibility into email authentication results, making it difficult to identify spoofing attempts or misconfigurations. Add a 'rua=mailto:dmarc-reports@" + domain + "' tag to receive daily aggregate reports.",
			Value:       dmarcRecord,
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489#section-6.2"},
		})
	}

	return results, nil
}

// checkDKIM checks for DKIM records at common selectors in parallel.
// Returns immediately when the first valid DKIM record is found.
func checkDKIM(ctx context.Context, resolver dnsResolver, domain string) []EmailCheckResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	found := make(chan struct{}, 1)
	var wg sync.WaitGroup

	for _, selector := range dkimSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			dkimDomain := sel + "._domainkey." + domain
			records, err := resolver.LookupTXT(ctx, dkimDomain)
			if err != nil {
				return
			}
			for _, record := range records {
				if strings.Contains(strings.ToLower(record), "v=dkim1") {
					select {
					case found <- struct{}{}:
						cancel() // stop remaining lookups
					default:
					}
					return
				}
			}
		}(selector)
	}

	// Wait for all goroutines in a separate goroutine so we can select
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-found:
		return nil
	case <-done:
		// All selectors checked, none found
	}

	return []EmailCheckResult{
		{
			FindingType: "missing-dkim",
			Severity:    shared.SeverityLow,
			Title:       "No DKIM Record Found",
			Description: "No DKIM (DomainKeys Identified Mail) record was found at common selectors (" + strings.Join(dkimSelectors, ", ") + ") for this domain. DKIM cryptographically signs outgoing emails, allowing recipients to verify the message was not altered in transit. Note: DKIM selectors are domain-specific, so a record may exist at a custom selector not checked here.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc6376"},
		},
	}
}

// checkZoneTransfer attempts AXFR queries against each nameserver for a domain.
// An open zone transfer is a confirmed critical recon finding — it exposes the
// entire DNS zone (internal hostnames, staging servers, database subdomains).
func checkZoneTransfer(ctx context.Context, resolver dnsResolver, domain string) ([]EmailCheckResult, error) {
	nameservers, err := resolver.LookupNS(ctx, domain)
	if err != nil && !isDNSNotFound(err) {
		return nil, fmt.Errorf("NS lookup: %w", err)
	}
	if len(nameservers) == 0 {
		return nil, nil
	}

	var vulnerableNS []string
	var totalRecords int
	var incomplete []error

	for _, ns := range nameservers {
		host := strings.TrimSuffix(ns.Host, ".")
		if host == "" {
			continue
		}

		// The nameserver comes from the target's own DNS, so it can point
		// anywhere, including internal addresses. Dial only a validated IP.
		addr, err := axfrAddress(ctx, host)
		if err != nil {
			continue
		}

		recordCount, err := tryAXFR(ctx, domain, addr)
		if err != nil {
			// The nameserver neither answered nor refused: whether it allows a transfer
			// is unknown, so the check is incomplete. The other nameservers are still tried.
			incomplete = append(incomplete, fmt.Errorf("AXFR against %s: %w", host, err))
			continue
		}
		if recordCount > 0 {
			vulnerableNS = append(vulnerableNS, fmt.Sprintf("%s (%d records)", host, recordCount))
			totalRecords += recordCount
		}
	}

	if len(vulnerableNS) == 0 {
		return nil, errors.Join(incomplete...)
	}

	return []EmailCheckResult{
		{
			FindingType: "dns-zone-transfer",
			Severity:    shared.SeverityHigh,
			Title:       "DNS Zone Transfer Allowed",
			Description: fmt.Sprintf(
				"The following nameservers allow public DNS zone transfers (AXFR) for %s, "+
					"exposing %d total DNS records: %s. This gives attackers a full map of internal "+
					"hostnames, staging servers, and services. Zone transfers should be restricted "+
					"to authorized secondary nameservers only.",
				domain, totalRecords, strings.Join(vulnerableNS, ", "),
			),
			Value:      strings.Join(vulnerableNS, ", "),
			References: []string{"https://datatracker.ietf.org/doc/html/rfc5936"},
		},
	}, errors.Join(incomplete...)
}

// axfrAddress resolves a nameserver host with the shared public-IP guard and
// returns "ip:53" for the first validated address. Any reserved answer rejects
// the nameserver, unless ALLOW_PRIVATE_TARGETS is set. Dialing the IP (not the
// host) stops a second lookup from being rebound to a private address.
func axfrAddress(ctx context.Context, host string) (string, error) {
	ips, err := shared.ResolvePublicIPs(ctx, host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ips[0].String(), "53"), nil
}

// tryAXFR attempts an AXFR transfer against a single nameserver address
// (ip:port, from axfrAddress).
// Returns the number of records received (0 when the transfer was refused), and an error
// when the attempt neither succeeded nor was refused (axfrFailure).
// Caps at maxAXFRRecords and cancels the transfer to stop the underlying read.
func tryAXFR(ctx context.Context, domain, addr string) (int, error) {
	const (
		maxAXFRRecords = 10000
		axfrTimeout    = 10 * time.Second
	)

	axfrCtx, axfrCancel := context.WithTimeout(ctx, axfrTimeout)
	defer axfrCancel()

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	t := new(dns.Transfer)
	t.DialTimeout = axfrTimeout
	t.ReadTimeout = axfrTimeout

	ch, err := t.In(m, addr)
	if err != nil {
		return 0, axfrFailure(err)
	}

	var count int
	for envelope := range ch {
		select {
		case <-axfrCtx.Done():
			go drainChannel(ch)
			return count, nil
		default:
		}
		if envelope.Error != nil {
			return 0, axfrFailure(envelope.Error)
		}
		count += len(envelope.RR)
		if count > maxAXFRRecords {
			go drainChannel(ch)
			return count, nil
		}
	}
	return count, nil
}

// axfrFailure returns err when it leaves open whether the nameserver allows a transfer (a
// timeout or a network error other than a refused connection), and nil for a definite "no":
// a refused connection or a DNS answer that refuses the transfer.
func axfrFailure(err error) error {
	var netErr net.Error
	if shared.IsConnRefused(err) {
		return nil
	}
	if errors.As(err, &netErr) {
		return err
	}
	return nil
}

// drainChannel consumes remaining envelopes so the dns.Transfer goroutine
// can complete its cleanup (close connection, close channel) instead of
// blocking forever on an unbuffered channel send.
func drainChannel(ch <-chan *dns.Envelope) {
	for range ch {
	}
}

// containsTag checks if a DMARC record contains a specific tag=value pair
func containsTag(record, tag, value string) bool {
	// DMARC tags are separated by semicolons
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == tag && strings.TrimSpace(kv[1]) == value {
			return true
		}
	}
	return false
}
