package scanner

import (
	"strings"

	"github.com/vulwall/scanners/internal/shared"
)

// HeaderCheckResult represents the result of checking a single security header
type HeaderCheckResult struct {
	HeaderName  string
	Present     bool
	Value       string
	IsSecure    bool
	Severity    string
	FindingType string
	Title       string
	Description string
	References  []string
}

// HeaderRule defines a security header check
type HeaderRule struct {
	Name        string
	Required    bool
	Severity    string // severity when missing
	FindingType string // finding type when missing (e.g., "missing-hsts")
	Title       string // title when missing
	Description string // description when missing
	References  []string
	CheckValue  func(value string) *HeaderCheckResult // optional: check if value is weak
}

// SecurityHeaderRules returns all header rules to check
func SecurityHeaderRules() []HeaderRule {
	return []HeaderRule{
		{
			Name:        "Strict-Transport-Security",
			Required:    true,
			Severity:    shared.SeverityHigh,
			FindingType: "missing-hsts",
			Title:       "Missing Strict-Transport-Security (HSTS) header",
			Description: "The server does not set the Strict-Transport-Security header. Without HSTS, browsers may connect over insecure HTTP, leaving users vulnerable to man-in-the-middle attacks and SSL stripping.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
				"https://owasp.org/www-project-secure-headers/#strict-transport-security",
			},
			CheckValue: checkHSTS,
		},
		{
			Name:        "Content-Security-Policy",
			Required:    true,
			Severity:    shared.SeverityMedium,
			FindingType: "missing-csp",
			Title:       "Missing Content-Security-Policy (CSP) header",
			Description: "The server does not set a Content-Security-Policy header. CSP helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks by controlling which resources the browser is allowed to load.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
				"https://owasp.org/www-project-secure-headers/#content-security-policy",
			},
			CheckValue: checkCSP,
		},
		{
			Name:        "X-Frame-Options",
			Required:    true,
			Severity:    shared.SeverityMedium,
			FindingType: "missing-x-frame-options",
			Title:       "Missing X-Frame-Options header",
			Description: "The server does not set the X-Frame-Options header. This allows the page to be embedded in iframes on other sites, making it vulnerable to clickjacking attacks.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
				"https://owasp.org/www-project-secure-headers/#x-frame-options",
			},
			CheckValue: nil,
		},
		{
			Name:        "X-Content-Type-Options",
			Required:    true,
			Severity:    shared.SeverityMedium,
			FindingType: "missing-x-content-type-options",
			Title:       "Missing X-Content-Type-Options header",
			Description: "The server does not set X-Content-Type-Options: nosniff. Without this header, browsers may MIME-sniff response content, potentially executing malicious content disguised as a benign file type.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
				"https://owasp.org/www-project-secure-headers/#x-content-type-options",
			},
			CheckValue: checkXContentTypeOptions,
		},
		{
			Name:        "Referrer-Policy",
			Required:    true,
			Severity:    shared.SeverityLow,
			FindingType: "missing-referrer-policy",
			Title:       "Missing Referrer-Policy header",
			Description: "The server does not set the Referrer-Policy header. Without this, the browser may leak the full URL (including sensitive query parameters) to third-party sites via the Referer header.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
				"https://owasp.org/www-project-secure-headers/#referrer-policy",
			},
			CheckValue: nil,
		},
		{
			Name:        "Permissions-Policy",
			Required:    true,
			Severity:    shared.SeverityLow,
			FindingType: "missing-permissions-policy",
			Title:       "Missing Permissions-Policy header",
			Description: "The server does not set the Permissions-Policy header. This header controls which browser features (camera, microphone, geolocation, etc.) the page can use, reducing the attack surface.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
				"https://owasp.org/www-project-secure-headers/#permissions-policy",
			},
			CheckValue: nil,
		},
	}
}

// DisclosureHeaderRules returns rules for headers that should NOT be present (information leakage)
func DisclosureHeaderRules() []string {
	return []string{"Server", "X-Powered-By"}
}

// checkHSTS validates the HSTS header value
func checkHSTS(value string) *HeaderCheckResult {
	lower := strings.ToLower(value)

	// Check for max-age
	if !strings.Contains(lower, "max-age") {
		return &HeaderCheckResult{
			HeaderName:  "Strict-Transport-Security",
			Present:     true,
			Value:       value,
			IsSecure:    false,
			Severity:    shared.SeverityHigh,
			FindingType: "weak-hsts",
			Title:       "Weak HSTS configuration: missing max-age directive",
			Description: "The Strict-Transport-Security header is present but does not include a max-age directive, making it ineffective.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
			},
		}
	}

	// Extract max-age value
	maxAge := extractMaxAge(lower)
	if maxAge >= 0 && maxAge < 31536000 { // less than 1 year
		return &HeaderCheckResult{
			HeaderName:  "Strict-Transport-Security",
			Present:     true,
			Value:       value,
			IsSecure:    false,
			Severity:    shared.SeverityMedium,
			FindingType: "weak-hsts",
			Title:       "Weak HSTS configuration: max-age too short",
			Description: "The Strict-Transport-Security max-age is set to less than one year (31536000 seconds). A longer max-age provides stronger protection against downgrade attacks.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
			},
		}
	}

	return nil // header is fine
}

// checkCSP validates the CSP header value
func checkCSP(value string) *HeaderCheckResult {
	lower := strings.ToLower(value)

	if strings.Contains(lower, "'unsafe-inline'") && strings.Contains(lower, "'unsafe-eval'") {
		return &HeaderCheckResult{
			HeaderName:  "Content-Security-Policy",
			Present:     true,
			Value:       value,
			IsSecure:    false,
			Severity:    shared.SeverityMedium,
			FindingType: "weak-csp",
			Title:       "Weak Content-Security-Policy: uses unsafe-inline and unsafe-eval",
			Description: "The Content-Security-Policy uses both 'unsafe-inline' and 'unsafe-eval' directives, which significantly weaken XSS protection by allowing inline scripts and dynamic code execution.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
			},
		}
	}

	if strings.Contains(lower, "'unsafe-inline'") {
		return &HeaderCheckResult{
			HeaderName:  "Content-Security-Policy",
			Present:     true,
			Value:       value,
			IsSecure:    false,
			Severity:    shared.SeverityLow,
			FindingType: "weak-csp",
			Title:       "Weak Content-Security-Policy: uses unsafe-inline",
			Description: "The Content-Security-Policy uses the 'unsafe-inline' directive, which weakens XSS protection by allowing inline scripts to execute.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
			},
		}
	}

	if strings.Contains(lower, "'unsafe-eval'") {
		return &HeaderCheckResult{
			HeaderName:  "Content-Security-Policy",
			Present:     true,
			Value:       value,
			IsSecure:    false,
			Severity:    shared.SeverityLow,
			FindingType: "weak-csp",
			Title:       "Weak Content-Security-Policy: uses unsafe-eval",
			Description: "The Content-Security-Policy uses the 'unsafe-eval' directive, which allows dynamic code execution via eval() and similar functions.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
			},
		}
	}

	return nil
}

// checkXContentTypeOptions validates the header value
func checkXContentTypeOptions(value string) *HeaderCheckResult {
	if strings.ToLower(strings.TrimSpace(value)) != "nosniff" {
		return &HeaderCheckResult{
			HeaderName:  "X-Content-Type-Options",
			Present:     true,
			Value:       value,
			IsSecure:    false,
			Severity:    shared.SeverityMedium,
			FindingType: "weak-x-content-type-options",
			Title:       "X-Content-Type-Options header has invalid value",
			Description: "The X-Content-Type-Options header is present but not set to 'nosniff'. The only valid value is 'nosniff'.",
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
			},
		}
	}
	return nil
}

// extractMaxAge extracts the max-age value from an HSTS header
func extractMaxAge(value string) int {
	idx := strings.Index(value, "max-age=")
	if idx == -1 {
		return -1
	}

	numStr := value[idx+len("max-age="):]
	// Trim to first non-digit
	end := 0
	for end < len(numStr) && numStr[end] >= '0' && numStr[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}

	result := 0
	for _, c := range numStr[:end] {
		result = result*10 + int(c-'0')
	}
	return result
}
