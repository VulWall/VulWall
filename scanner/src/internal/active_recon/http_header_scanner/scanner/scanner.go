package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// Scanner defines the interface for HTTP header security scanning
type Scanner interface {
	Scan(ctx context.Context, targetURL string) ([]HeaderCheckResult, error)
}

// HTTPHeaderScanner implements the Scanner interface
type HTTPHeaderScanner struct {
	httpClient *http.Client
	logger     *zap.Logger
	rules      []HeaderRule
	disclosure []string
}

// NewScanner creates a new HTTP header scanner
func NewScanner(logger *zap.Logger) *HTTPHeaderScanner {
	return &HTTPHeaderScanner{
		httpClient: createHTTPClient(),
		logger:     logger,
		rules:      SecurityHeaderRules(),
		disclosure: DisclosureHeaderRules(),
	}
}

// Scan fetches HTTP headers from the target URL and checks them against security rules
func (s *HTTPHeaderScanner) Scan(ctx context.Context, targetURL string) ([]HeaderCheckResult, error) {
	headers, err := s.fetchHeaders(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch headers from %s: %w", targetURL, err)
	}

	var results []HeaderCheckResult

	// Check required security headers
	for _, rule := range s.rules {
		value, present := getHeaderCaseInsensitive(headers, rule.Name)

		if !present {
			results = append(results, HeaderCheckResult{
				HeaderName:  rule.Name,
				Present:     false,
				IsSecure:    false,
				Severity:    rule.Severity,
				FindingType: rule.FindingType,
				Title:       rule.Title,
				Description: rule.Description,
				References:  rule.References,
			})
			continue
		}

		// Header present — check value if validator exists
		if rule.CheckValue != nil {
			if check := rule.CheckValue(value); check != nil {
				results = append(results, *check)
			}
		}
	}

	// Check disclosure headers (should NOT be present)
	for _, headerName := range s.disclosure {
		value, present := getHeaderCaseInsensitive(headers, headerName)
		if present && value != "" {
			results = append(results, HeaderCheckResult{
				HeaderName:  headerName,
				Present:     true,
				Value:       value,
				IsSecure:    false,
				Severity:    shared.SeverityInfo,
				FindingType: fmt.Sprintf("header-disclosure-%s", strings.ToLower(headerName)),
				Title:       fmt.Sprintf("Information disclosure via %s header", headerName),
				Description: fmt.Sprintf("The %s header is present and reveals server technology information (%s). This helps attackers identify specific software versions and target known vulnerabilities.", headerName, value),
				References: []string{
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
				},
			})
		}
	}

	// Check CORS misconfiguration (requires its own request with Origin header)
	results = append(results, s.checkCORS(ctx, targetURL)...)

	// Check HTTPS redirect (only for HTTP URLs)
	if strings.HasPrefix(targetURL, "http://") {
		results = append(results, s.checkHTTPSRedirect(ctx, targetURL)...)
	}

	// Check security.txt (only on HTTPS to avoid duplicate findings)
	if strings.HasPrefix(targetURL, "https://") {
		results = append(results, s.checkSecurityTxt(ctx, targetURL)...)
	}

	return results, nil
}

// checkCORS sends a request with a spoofed Origin header and checks if the server
// reflects it or uses a wildcard — both indicate CORS misconfiguration.
func (s *HTTPHeaderScanner) checkCORS(ctx context.Context, targetURL string) []HeaderCheckResult {
	const testOrigin = "https://evil-cors-test.com"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", shared.DefaultUserAgent)
	req.Header.Set("Origin", testOrigin)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil // No CORS header — not misconfigured
	}

	acac := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	var results []HeaderCheckResult

	switch {
	case acao == testOrigin:
		// Origin is reflected back — worst case, fully exploitable
		description := fmt.Sprintf(
			"The server reflects the arbitrary Origin header value back in Access-Control-Allow-Origin (%s). "+
				"This allows any website to make cross-origin requests to your application, "+
				"potentially stealing sensitive data from logged-in users.",
			acao,
		)
		if acac {
			description += " This is compounded by Access-Control-Allow-Credentials: true, which means cookies and authentication headers are included in cross-origin requests."
		}

		results = append(results, HeaderCheckResult{
			HeaderName:  "Access-Control-Allow-Origin",
			Present:     true,
			Value:       acao,
			IsSecure:    false,
			Severity:    shared.SeverityHigh,
			FindingType: "cors-origin-reflected",
			Title:       "CORS Reflects Arbitrary Origins",
			Description: description,
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
			},
		})

	case acao == "*":
		if acac {
			// Wildcard + credentials — browsers block this, but it signals misconfiguration
			results = append(results, HeaderCheckResult{
				HeaderName:  "Access-Control-Allow-Origin",
				Present:     true,
				Value:       acao,
				IsSecure:    false,
				Severity:    shared.SeverityMedium,
				FindingType: "cors-credentials-with-wildcard",
				Title:       "CORS Allows Credentials with Wildcard Origin",
				Description: "The server sets Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Modern browsers block this combination, but it indicates a fundamental CORS misconfiguration that should be corrected.",
				References: []string{
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
				},
			})
		} else {
			results = append(results, HeaderCheckResult{
				HeaderName:  "Access-Control-Allow-Origin",
				Present:     true,
				Value:       acao,
				IsSecure:    false,
				Severity:    shared.SeverityMedium,
				FindingType: "cors-wildcard-origin",
				Title:       "CORS Allows Any Origin",
				Description: "The server sets Access-Control-Allow-Origin: *, allowing any website to read responses from your application. While credentials are not included with wildcard origins, this may still expose sensitive data from unauthenticated endpoints.",
				References: []string{
					"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
					"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
				},
			})
		}
	}

	return results
}

// checkSecurityTxt checks for the presence of a security.txt file at the
// well-known URI and legacy root path (RFC 9116 Section 3).
func (s *HTTPHeaderScanner) checkSecurityTxt(ctx context.Context, targetURL string) []HeaderCheckResult {
	baseURL := strings.TrimRight(targetURL, "/")

	// Check both RFC 9116 well-known path and legacy root path
	paths := []string{"/.well-known/security.txt", "/security.txt"}
	for _, path := range paths {
		if s.hasSecurityTxt(ctx, baseURL+path) {
			return nil
		}
	}

	return []HeaderCheckResult{
		{
			HeaderName:  "security.txt",
			Present:     false,
			IsSecure:    false,
			Severity:    shared.SeverityInfo,
			FindingType: "missing-security-txt",
			Title:       "Missing security.txt",
			Description: "No security.txt file was found at /.well-known/security.txt. This file (RFC 9116) provides a standardized way to communicate your vulnerability disclosure policy, making it easy for security researchers to report issues responsibly. Many security questionnaires now ask whether a vulnerability disclosure policy is in place.",
			References: []string{
				"https://datatracker.ietf.org/doc/html/rfc9116",
				"https://securitytxt.org/",
			},
		},
	}
}

// hasSecurityTxt checks if a security.txt file exists at the given URL.
func (s *HTTPHeaderScanner) hasSecurityTxt(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		ct := resp.Header.Get("Content-Type")
		return strings.Contains(ct, "text/plain")
	}
	return false
}

// checkHTTPSRedirect checks whether an HTTP URL redirects to HTTPS.
// A missing redirect means users can be served over plaintext.
func (s *HTTPHeaderScanner) checkHTTPSRedirect(ctx context.Context, targetURL string) []HeaderCheckResult {
	// Use a client that does not follow redirects
	noRedirectClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: s.httpClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if response is a redirect to HTTPS
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.HasPrefix(strings.ToLower(location), "https://") {
			return nil // Correctly redirects to HTTPS
		}
	}

	return []HeaderCheckResult{
		{
			HeaderName:  "Location",
			Present:     false,
			IsSecure:    false,
			Severity:    shared.SeverityMedium,
			FindingType: "missing-https-redirect",
			Title:       "HTTP Does Not Redirect to HTTPS",
			Description: "The HTTP version of this site does not redirect to HTTPS. Users or links pointing to the HTTP URL will be served over an unencrypted connection, exposing traffic to interception and man-in-the-middle attacks.",
			References: []string{
				"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
				"https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
			},
		},
	}
}

// fetchHeaders sends a GET request and returns the response headers
func (s *HTTPHeaderScanner) fetchHeaders(ctx context.Context, targetURL string) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return resp.Header, nil
}

// getHeaderCaseInsensitive looks up a header by canonical name
func getHeaderCaseInsensitive(headers http.Header, name string) (string, bool) {
	value := headers.Get(name)
	if value != "" {
		return value, true
	}
	return "", false
}

// createHTTPClient creates an optimized HTTP client with timeouts
func createHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ResponseHeaderTimeout: 10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		// Don't follow redirects — we want headers from the original response
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
