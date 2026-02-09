package patterns

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vulwall/scanners/internal/shared"
	"go.uber.org/zap"
)

// HTTPResponse represents an HTTP response from probing
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Cookies    map[string]string
	Body       string
}

// Detector performs WAF detection using HTTP probing and pattern matching
type Detector struct {
	client     *http.Client
	logger     *zap.Logger
	signatures []WAFSignature
}

// loadSignaturesFromJSON loads WAF signatures from a JSON file
func loadSignaturesFromJSON(path string) ([]WAFSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var config struct {
		Signatures []WAFSignature `json:"signatures"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return config.Signatures, nil
}

// NewDetector creates a new WAF detector
func NewDetector(logger *zap.Logger, rulesPath string) (*Detector, error) {
	// Load signatures from JSON file
	signatures, err := loadSignaturesFromJSON(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signatures: %w", err)
	}

	// Compile all signature patterns
	if err := CompileSignatures(signatures); err != nil {
		return nil, fmt.Errorf("failed to compile signatures: %w", err)
	}

	// Create HTTP client with timeout and TLS config
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip cert verification for WAF detection
			},
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects
			return http.ErrUseLastResponse
		},
	}

	return &Detector{
		client:     client,
		logger:     logger,
		signatures: signatures,
	}, nil
}

// Detect performs WAF detection on the given target URL
func (d *Detector) Detect(ctx context.Context, targetURL string) (string, error) {
	d.logger.Info("Starting WAF detection",
		zap.String("target", targetURL),
	)

	// Ensure target has a scheme
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		// Try HTTPS first
		targetURL = "https://" + targetURL
	}

	// Step 1: Normal request
	normalResp, err := d.probe(ctx, targetURL, "")
	if err != nil {
		d.logger.Warn("Normal request failed",
			zap.String("target", targetURL),
			zap.Error(err),
		)
		// Continue with attack requests even if normal fails
		normalResp = nil
	}

	// Step 2: Attack requests with various payloads
	attackPayloads := []string{
		"<script>alert('XSS')</script>",              // XSS
		"' OR '1'='1",                                // SQLi
		"../../../../etc/passwd",                     // LFI
		"<img src=x onerror=alert('XSS')>",           // XSS variant
		"UNION SELECT NULL, NULL, NULL--",            // SQLi variant
		"<iframe src='javascript:alert(1)'>",         // XSS iframe
		"' AND 1=1--",                                // SQLi
		"../../../../../windows/system32/config/sam", // LFI Windows
		"<?php system($_GET['cmd']); ?>",             // Command injection
		"';DROP TABLE users--",                       // SQLi drop table
	}

	var attackResponses []*HTTPResponse
	for _, payload := range attackPayloads {
		resp, err := d.probe(ctx, targetURL, payload)
		if err != nil {
			d.logger.Debug("Attack request failed",
				zap.String("target", targetURL),
				zap.String("payload", payload),
				zap.Error(err),
			)
			continue
		}
		attackResponses = append(attackResponses, resp)

		// If we get a block response, we likely triggered the WAF
		if d.isBlockResponse(resp) {
			break
		}
	}

	// Step 3: Match responses against signatures
	// Check normal response first, then attack responses
	allResponses := []*HTTPResponse{}
	if normalResp != nil {
		allResponses = append(allResponses, normalResp)
	}
	allResponses = append(allResponses, attackResponses...)

	for _, resp := range allResponses {
		if wafName := d.matchSignatures(resp); wafName != "" {
			d.logger.Info("WAF detected",
				zap.String("target", targetURL),
				zap.String("waf", wafName),
			)
			return wafName, nil
		}
	}

	d.logger.Info("No WAF detected",
		zap.String("target", targetURL),
	)
	return "", nil
}

// probe sends an HTTP request with optional payload
func (d *Detector) probe(ctx context.Context, targetURL string, payload string) (*HTTPResponse, error) {
	// Build URL with payload if provided
	url := targetURL
	if payload != "" {
		separator := "?"
		if strings.Contains(targetURL, "?") {
			separator = "&"
		}
		url = fmt.Sprintf("%s%sx=%s", targetURL, separator, payload)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add common headers
	req.Header.Set("User-Agent", shared.DefaultUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	// Send request
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Extract cookies
	cookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Cookies:    cookies,
		Body:       string(body),
	}, nil
}

// isBlockResponse checks if the response indicates a block
func (d *Detector) isBlockResponse(resp *HTTPResponse) bool {
	// Common WAF block status codes
	blockCodes := []int{403, 406, 418, 429, 499, 503}
	for _, code := range blockCodes {
		if resp.StatusCode == code {
			return true
		}
	}
	return false
}

// matchSignatures matches response against all WAF signatures
func (d *Detector) matchSignatures(resp *HTTPResponse) string {
	if resp == nil {
		return ""
	}

	// Sort signatures by priority (higher first)
	// Already sorted in AllSignatures, but we iterate in order

	for _, sig := range d.signatures {
		if d.matchSignature(resp, sig) {
			return sig.Name
		}
	}

	return ""
}

// matchSignature checks if a response matches a specific WAF signature
func (d *Detector) matchSignature(resp *HTTPResponse, sig WAFSignature) bool {
	matchCount := 0
	requiredMatches := 2 // Require at least 2 checks to match for confidence

	for _, check := range sig.Checks {
		if d.matchCheck(resp, check) {
			matchCount++
			if matchCount >= requiredMatches {
				return true
			}
		}
	}

	return false
}

// matchCheck performs a single check against the response
func (d *Detector) matchCheck(resp *HTTPResponse, check Check) bool {
	if check.Regex == nil {
		return false
	}

	switch check.Type {
	case CheckTypeHeader:
		// Check specific header
		if check.Key != "" {
			headerValue := resp.Headers.Get(check.Key)
			if headerValue != "" && check.Regex.MatchString(headerValue) {
				return true
			}
		} else {
			// Check all headers
			for _, values := range resp.Headers {
				for _, value := range values {
					if check.Regex.MatchString(value) {
						return true
					}
				}
			}
		}

	case CheckTypeCookie:
		// Check cookies (both names and values)
		for name, value := range resp.Cookies {
			if check.Regex.MatchString(name) || check.Regex.MatchString(value) {
				return true
			}
		}

	case CheckTypeContent:
		// Check response body
		if check.Regex.MatchString(resp.Body) {
			return true
		}

	case CheckTypeCode:
		// Check status code
		statusStr := strconv.Itoa(resp.StatusCode)
		if check.Regex.MatchString(statusStr) {
			return true
		}
	}

	return false
}
