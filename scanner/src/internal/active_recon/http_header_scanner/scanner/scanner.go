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
		// Origin is reflected back — worst case
		severity := shared.SeverityHigh
		description := fmt.Sprintf(
			"The server reflects the arbitrary Origin header value back in Access-Control-Allow-Origin (%s). "+
				"This allows any website to make authenticated cross-origin requests to your application, "+
				"potentially stealing sensitive data from logged-in users.",
			acao,
		)
		if acac {
			description += " This is compounded by Access-Control-Allow-Credentials: true, which means cookies and authentication headers are included in cross-origin requests."
		}

		findingType := "cors-origin-reflected"
		if acac {
			findingType = "cors-credentials-with-wildcard"
		}

		results = append(results, HeaderCheckResult{
			HeaderName:  "Access-Control-Allow-Origin",
			Present:     true,
			Value:       acao,
			IsSecure:    false,
			Severity:    severity,
			FindingType: findingType,
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
				Severity:    shared.SeverityHigh,
				FindingType: "cors-credentials-with-wildcard",
				Title:       "CORS Allows Credentials with Wildcard Origin",
				Description: "The server sets Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. While modern browsers block this combination, it indicates a fundamental CORS misconfiguration that may be exploitable in older clients or via other attack vectors.",
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
