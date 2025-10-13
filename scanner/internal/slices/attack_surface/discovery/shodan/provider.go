package shodan

import (
	"context"

	"github.com/vulwall/scanners/internal/slices/attack_surface/discovery"
	"go.uber.org/zap"
)

// Provider implements discovery.AttackSurfaceProvider for Shodan subdomain discovery
type Provider struct {
	client *Client
	logger *zap.Logger
}

// NewProvider creates a new Shodan provider
func NewProvider(apiKey string, logger *zap.Logger) *Provider {
	return &Provider{
		client: NewClient(apiKey, logger),
		logger: logger,
	}
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "shodan"
}

// Discover discovers subdomains using Shodan DNS API
func (p *Provider) Discover(ctx context.Context, target discovery.DiscoveryTarget) ([]discovery.DiscoveredAsset, error) {
	// Shodan only works with domains
	if target.Type != "domain" {
		p.logger.Debug("Skipping non-domain target for Shodan", zap.String("type", target.Type))
		return nil, nil
	}

	// Discover subdomains using Shodan client
	subdomains, err := p.client.DiscoverSubdomains(ctx, target.Host)
	if err != nil {
		return nil, err
	}

	if len(subdomains) == 0 {
		return []discovery.DiscoveredAsset{}, nil
	}

	// Convert subdomains to DiscoveredAsset format
	assets := make([]discovery.DiscoveredAsset, 0, len(subdomains))
	for _, subdomainName := range subdomains {
		// Skip empty strings and wildcards
		if subdomainName == "" || subdomainName == "*" {
			continue
		}

		// Build the full subdomain (e.g., "api" + ".example.com")
		fullSubdomain := subdomainName
		if !contains(subdomainName, target.Host) {
			fullSubdomain = subdomainName + "." + target.Host
		}

		assets = append(assets, discovery.DiscoveredAsset{
			Host:     fullSubdomain,
			Port:     nil, // Subdomains don't have ports
			Protocol: nil, // Subdomains don't have protocols
			Metadata: map[string]interface{}{
				"source": "shodan",
			},
		})
	}

	return assets, nil
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[len(s)-len(substr)-1:] == "."+substr || s[:len(substr)+1] == substr+"."))
}
