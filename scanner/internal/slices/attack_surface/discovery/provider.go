package discovery

import "context"

// AttackSurfaceProvider defines the interface for attack surface discovery providers
// Providers can discover various assets: subdomains, IP addresses, open ports, services, etc.
type AttackSurfaceProvider interface {
	// Name returns the provider name for logging and identification
	Name() string

	// Discover performs discovery based on the target and returns discovered assets
	Discover(ctx context.Context, target DiscoveryTarget) ([]DiscoveredAsset, error)
}

// DiscoveryTarget represents the target for discovery
type DiscoveryTarget struct {
	Host     string  // Domain name or IP address
	Port     *int    // Optional port to scan
	Protocol *string // Optional protocol (tcp, udp, sctp, icmp)
	Type     string  // Target type: "domain", "ip", "cidr"
}

// DiscoveredAsset represents an asset discovered by a provider
type DiscoveredAsset struct {
	Host     string                 // Discovered hostname or IP
	Port     *int                   // Discovered port (nil for non-port assets like subdomains)
	Protocol *string                // Protocol (tcp, udp, sctp, icmp) - nil for non-port assets
	Metadata map[string]interface{} // Provider-specific metadata
}
