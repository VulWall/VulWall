package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
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
	headers, status, body, err := s.fetchHeaders(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch headers from %s: %w", targetURL, err)
	}
	// The checks still run on an error or challenge page, but its headers may be the WAF's or
	// the proxy's, not the application's: the check is then incomplete.
	incomplete := shared.BlockedResponse(targetURL, status, headers, body)

	var results []HeaderCheckResult

	// Check required security headers
	for _, rule := range s.rules {
		value, present := getHeaderCaseInsensitive(headers, rule.Name)

		if !present {
			// Skip missing X-Frame-Options if CSP frame-ancestors is set (it supersedes X-Frame-Options)
			if rule.Name == "X-Frame-Options" {
				if csp, hasCSP := getHeaderCaseInsensitive(headers, "Content-Security-Policy"); hasCSP &&
					strings.Contains(strings.ToLower(csp), "frame-ancestors") {
					continue
				}
			}

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
	cors, corsErr := s.checkCORS(ctx, targetURL)
	results = append(results, cors...)

	// Check HTTPS redirect (only for HTTP URLs)
	var redirectErr error
	if strings.HasPrefix(targetURL, "http://") {
		var redirect []HeaderCheckResult
		redirect, redirectErr = s.checkHTTPSRedirect(ctx, targetURL)
		results = append(results, redirect...)
	}

	// Check security.txt (only on HTTPS to avoid duplicate findings)
	if strings.HasPrefix(targetURL, "https://") {
		results = append(results, s.checkSecurityTxt(ctx, targetURL)...)
	}

	return results, errors.Join(incomplete, corsErr, redirectErr)
}

// checkCORS sends a request with a spoofed Origin header and checks if the server
// reflects it or uses a wildcard — both indicate CORS misconfiguration.
func (s *HTTPHeaderScanner) checkCORS(ctx context.Context, targetURL string) ([]HeaderCheckResult, error) {
	const testOrigin = "https://evil-cors-test.com"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", shared.DefaultUserAgent)
	req.Header.Set("Origin", testOrigin)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CORS check: %w", err)
	}
	defer resp.Body.Close()
	blocked := shared.BlockedResponse(targetURL, resp.StatusCode, resp.Header, nil)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil, blocked // No CORS header — not misconfigured
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
				Severity:    shared.SeverityLow,
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

	return results, blocked
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
func (s *HTTPHeaderScanner) checkHTTPSRedirect(ctx context.Context, targetURL string) ([]HeaderCheckResult, error) {
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
		return nil, err
	}
	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTPS redirect check: %w", err)
	}
	defer resp.Body.Close()
	blocked := shared.BlockedResponse(targetURL, resp.StatusCode, resp.Header, nil)

	// Check if response is a redirect to HTTPS
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.HasPrefix(strings.ToLower(location), "https://") {
			return nil, blocked // Correctly redirects to HTTPS
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
	}, blocked
}

// fetchHeaders sends a GET request and returns the response headers, status and the start of
// the body (enough for shared.BlockedResponse to recognize a WAF challenge page).
func (s *HTTPHeaderScanner) fetchHeaders(ctx context.Context, targetURL string) (http.Header, int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", shared.DefaultUserAgent)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, shared.BlockedBodyPrefix))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("read body: %w", err)
	}
	return resp.Header, resp.StatusCode, body, nil
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
		DialContext: shared.SSRFSafeDialContext(&net.Dialer{
			Timeout: 5 * time.Second,
		}),
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
