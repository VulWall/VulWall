package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	baseURL       = "https://api.shodan.io"
	maxRetries    = 3
	initialBackoff = 1 * time.Second
)

// Client handles Shodan API interactions
type Client struct {
	apiKey     string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewClient creates a new Shodan API client with optimized HTTP settings
func NewClient(apiKey string, logger *zap.Logger) *Client {
	transport := &http.Transport{
		ResponseHeaderTimeout: 15 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       30 * time.Second,
	}

	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		logger: logger,
	}
}

// DiscoverSubdomains discovers subdomains for a given domain using Shodan DNS API
func (c *Client) DiscoverSubdomains(ctx context.Context, domain string) ([]string, error) {
	if c.apiKey == "" {
		c.logger.Warn("Shodan API key not configured, skipping Shodan discovery")
		return nil, nil
	}

	c.logger.Info("Discovering subdomains via Shodan",
		zap.String("domain", domain),
	)

	url := fmt.Sprintf("%s/dns/domain/%s?key=%s", baseURL, domain, c.apiKey)

	body, err := c.doRequestWithRetry(ctx, url)
	if err != nil {
		return nil, err
	}

	if body == nil {
		// 404 - no records found
		return []string{}, nil
	}

	var shodanResp DNSDomainResponse
	if err := json.Unmarshal(body, &shodanResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	c.logger.Info("Shodan subdomain discovery complete",
		zap.String("domain", domain),
		zap.Int("subdomains_found", len(shodanResp.Subdomains)),
	)

	return shodanResp.Subdomains, nil
}

// GetHostInfo retrieves host information including open ports using Shodan Host API
// Returns nil, nil if the IP is not found in Shodan's database (404)
func (c *Client) GetHostInfo(ctx context.Context, ip string) (*HostInfo, error) {
	if c.apiKey == "" {
		c.logger.Warn("Shodan API key not configured, skipping Shodan lookup")
		return nil, nil
	}

	c.logger.Debug("Looking up host info via Shodan",
		zap.String("ip", ip),
	)

	url := fmt.Sprintf("%s/shodan/host/%s?key=%s", baseURL, ip, c.apiKey)

	body, err := c.doRequestWithRetry(ctx, url)
	if err != nil {
		return nil, err
	}

	if body == nil {
		// 404 - IP not found in Shodan database
		c.logger.Debug("IP not found in Shodan database",
			zap.String("ip", ip),
		)
		return nil, nil
	}

	var hostInfo HostInfo
	if err := json.Unmarshal(body, &hostInfo); err != nil {
		return nil, fmt.Errorf("failed to parse host info response: %w", err)
	}

	c.logger.Info("Shodan host lookup complete",
		zap.String("ip", ip),
		zap.Int("ports_found", len(hostInfo.Ports)),
	)

	return &hostInfo, nil
}

// doRequestWithRetry executes an HTTP request with exponential backoff retry logic
// Returns nil body for 404 responses (not found)
func (c *Client) doRequestWithRetry(ctx context.Context, url string) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Apply backoff delay for retries
		if attempt > 0 {
			backoff := initialBackoff * time.Duration(1<<(attempt-1)) // 1s, 2s, 4s
			c.logger.Debug("Retrying Shodan request",
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
			)

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		body, err, shouldRetry := c.doRequest(ctx, url)
		if err == nil {
			return body, nil
		}

		lastErr = err

		if !shouldRetry {
			return nil, err
		}
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// doRequest executes a single HTTP request
// Returns (body, error, shouldRetry)
func (c *Client) doRequest(ctx context.Context, url string) ([]byte, error, bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err), false
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network errors are retryable
		return nil, fmt.Errorf("failed to execute request: %w", err), isRetryableError(err)
	}
	defer resp.Body.Close()

	// Handle specific status codes
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err), false
		}
		return body, nil, false

	case http.StatusNotFound:
		// 404 - resource not found (IP not in database, no DNS records)
		return nil, nil, false

	case http.StatusUnauthorized:
		return nil, fmt.Errorf("unauthorized: invalid Shodan API key"), false

	case http.StatusTooManyRequests:
		// 429 - rate limit exceeded, retry
		return nil, fmt.Errorf("rate limit exceeded"), true

	default:
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 500 {
			// 5xx errors are retryable
			return nil, fmt.Errorf("shodan API error (status %d): %s", resp.StatusCode, string(body)), true
		}
		// Other 4xx errors are not retryable
		return nil, fmt.Errorf("shodan API error (status %d): %s", resp.StatusCode, string(body)), false
	}
}

// isRetryableError determines if a network error should be retried
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "temporary failure")
}
