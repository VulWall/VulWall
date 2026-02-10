package email_security_scanner

import (
	"context"
	"net"
	"strings"

	"github.com/vulwall/scanners/internal/shared"
)

// Common DKIM selectors to check
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "dkim"}

// checkSPF performs SPF record validation for a domain
func checkSPF(ctx context.Context, resolver *net.Resolver, domain string) []EmailCheckResult {
	var results []EmailCheckResult

	records, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		// No TXT records at all — SPF is missing
		results = append(results, EmailCheckResult{
			FindingType: "missing-spf",
			Severity:    shared.SeverityMedium,
			Title:       "Missing SPF Record",
			Description: "No SPF (Sender Policy Framework) record was found for this domain. Without SPF, attackers can send emails that appear to come from this domain, enabling phishing and spam campaigns. SPF helps receiving mail servers verify that incoming mail from a domain comes from an authorized IP address.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
		})
		return results
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
		return results
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

	return results
}

// checkDMARC performs DMARC record validation for a domain
func checkDMARC(ctx context.Context, resolver *net.Resolver, domain string) []EmailCheckResult {
	var results []EmailCheckResult

	dmarcDomain := "_dmarc." + domain
	records, err := resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		results = append(results, EmailCheckResult{
			FindingType: "missing-dmarc",
			Severity:    shared.SeverityMedium,
			Title:       "Missing DMARC Record",
			Description: "No DMARC (Domain-based Message Authentication, Reporting & Conformance) record was found at _dmarc." + domain + ". DMARC builds on SPF and DKIM to provide domain-level email authentication. Without DMARC, there is no policy instructing receiving servers how to handle emails that fail authentication checks, leaving the domain vulnerable to spoofing.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
		})
		return results
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
		return results
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

	return results
}

// checkDKIM checks for DKIM records at common selectors
func checkDKIM(ctx context.Context, resolver *net.Resolver, domain string) []EmailCheckResult {
	for _, selector := range dkimSelectors {
		dkimDomain := selector + "._domainkey." + domain
		records, err := resolver.LookupTXT(ctx, dkimDomain)
		if err != nil {
			continue
		}

		for _, record := range records {
			if strings.Contains(strings.ToLower(record), "v=dkim1") {
				// Found a valid DKIM record — no finding to report
				return nil
			}
		}
	}

	// No DKIM record found at any common selector
	return []EmailCheckResult{
		{
			FindingType: "missing-dkim",
			Severity:    shared.SeverityInfo,
			Title:       "No DKIM Record Found",
			Description: "No DKIM (DomainKeys Identified Mail) record was found at common selectors (" + strings.Join(dkimSelectors, ", ") + ") for this domain. DKIM cryptographically signs outgoing emails, allowing recipients to verify the message was not altered in transit. Note: DKIM selectors are domain-specific, so a record may exist at a custom selector not checked here.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc6376"},
		},
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
