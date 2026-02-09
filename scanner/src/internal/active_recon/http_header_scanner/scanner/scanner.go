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

	return results, nil
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
