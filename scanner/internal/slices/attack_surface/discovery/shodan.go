package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ShodanClient handles Shodan API interactions for subdomain discovery
type ShodanClient struct {
	apiKey     string
	httpClient *http.Client
	logger     *zap.Logger
}

// ShodanDNSDomainResponse represents Shodan DNS domain API response
type ShodanDNSDomainResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
}

// NewShodanClient creates a new Shodan API client
func NewShodanClient(apiKey string, logger *zap.Logger) *ShodanClient {
	return &ShodanClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

// DiscoverSubdomains discovers subdomains for a given domain using Shodan DNS API
func (s *ShodanClient) DiscoverSubdomains(ctx context.Context, domain string) ([]string, error) {
	if s.apiKey == "" {
		s.logger.Warn("Shodan API key not configured, skipping Shodan discovery")
		return nil, nil
	}

	s.logger.Info("Discovering subdomains via Shodan",
		zap.String("domain", domain),
	)

	// Shodan DNS domain endpoint
	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, s.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized: invalid Shodan API key")
	}

	if resp.StatusCode == 404 {
		s.logger.Info("No DNS records found for domain in Shodan", zap.String("domain", domain))
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

	var shodanResp ShodanDNSDomainResponse
	if err := json.Unmarshal(body, &shodanResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	s.logger.Info("Shodan subdomain discovery complete",
		zap.String("domain", domain),
		zap.Int("subdomains_found", len(shodanResp.Subdomains)),
	)

	return shodanResp.Subdomains, nil
}
