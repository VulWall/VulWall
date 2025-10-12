package discovery

import (
	"context"

	"go.uber.org/zap"
)

// ShodanProvider implements AttackSurfaceProvider for Shodan subdomain discovery
type ShodanProvider struct {
	client *ShodanClient
	logger *zap.Logger
}

// NewShodanProvider creates a new Shodan provider
func NewShodanProvider(apiKey string, logger *zap.Logger) *ShodanProvider {
	return &ShodanProvider{
		client: NewShodanClient(apiKey, logger),
		logger: logger,
	}
}

// Name returns the provider name
func (p *ShodanProvider) Name() string {
	return "shodan"
}

// Discover discovers subdomains using Shodan DNS API
func (p *ShodanProvider) Discover(ctx context.Context, target DiscoveryTarget) ([]DiscoveredAsset, error) {
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
		return []DiscoveredAsset{}, nil
	}

	// Convert subdomains to DiscoveredAsset format
	assets := make([]DiscoveredAsset, 0, len(subdomains))
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

		assets = append(assets, DiscoveredAsset{
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
