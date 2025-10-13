package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Client handles Shodan API interactions for subdomain discovery
type Client struct {
	apiKey     string
	httpClient *http.Client
	logger     *zap.Logger
}

// DNSDomainResponse represents Shodan DNS domain API response
type DNSDomainResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

// NewClient creates a new Shodan API client
func NewClient(apiKey string, logger *zap.Logger) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
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

	// Shodan DNS domain endpoint
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized: invalid Shodan API key")
	}

	if resp.StatusCode == 404 {
		c.logger.Info("No DNS records found for domain in Shodan", zap.String("domain", domain))
		return []string{}, nil
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shodan API error (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
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
