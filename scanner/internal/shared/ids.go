package shared

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// UUID namespace for VulWall discoveries
// This ensures our UUIDs don't collide with other systems
var DiscoveryNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

// DetermineDomainAssetType determines if a hostname is a domain or subdomain
// This function is ONLY for domain/subdomain classification, not for IPs or ports
// Note: parentID in this context refers to the parent domain, indicating a subdomain relationship
func DetermineDomainAssetType(host string, parentID *string) string {
	// If parentID is specified, it's a subdomain under a parent domain
	if parentID != nil && *parentID != "" {
		return AssetTypeSubdomain
	}

	// Count dots to determine if subdomain
	// example.com = 1 dot = domain
	// api.example.com = 2 dots = subdomain
	dotCount := strings.Count(host, ".")
	if dotCount > 1 {
		return AssetTypeSubdomain
	}

	return AssetTypeDomain
}

// GenerateDomainID creates a deterministic UUID for a domain
// Same domain always produces the same ID
func GenerateDomainID(domain string) string {
	// Normalize domain to lowercase
	normalized := strings.ToLower(strings.TrimSpace(domain))
	return uuid.NewSHA1(DiscoveryNamespace, []byte("domain:"+normalized)).String()
}

// GenerateSubdomainID creates a deterministic UUID for a subdomain
// Same subdomain always produces the same ID
func GenerateSubdomainID(subdomain string) string {
	// Normalize subdomain to lowercase
	normalized := strings.ToLower(strings.TrimSpace(subdomain))
	return uuid.NewSHA1(DiscoveryNamespace, []byte("subdomain:"+normalized)).String()
}

// GenerateIPID creates a deterministic UUID for an IP address
// Same IP always produces the same ID
func GenerateIPID(ip string) string {
	// Normalize IP (trim whitespace)
	normalized := strings.TrimSpace(ip)
	return uuid.NewSHA1(DiscoveryNamespace, []byte("ip:"+normalized)).String()
}

// GeneratePortID creates a deterministic UUID for a port on an IP
// Protocol matters: 192.168.1.1:80/tcp != 192.168.1.1:80/udp
func GeneratePortID(ip string, port int, protocol string) string {
	// Normalize inputs
	normalizedIP := strings.TrimSpace(ip)
	normalizedProto := strings.ToLower(strings.TrimSpace(protocol))

	// Format: ip:port/protocol
	key := fmt.Sprintf("port:%s:%d/%s", normalizedIP, port, normalizedProto)
	return uuid.NewSHA1(DiscoveryNamespace, []byte(key)).String()
}

// GenerateDiscoveryID is a convenience function that generates the appropriate ID
// based on asset type. This is useful when you have all the information but aren't
// sure which specific function to call.
func GenerateDiscoveryID(assetType string, host string, ip *string, port *int, protocol *string) string {
	switch assetType {
	case AssetTypeDomain:
		return GenerateDomainID(host)
	case AssetTypeSubdomain:
		return GenerateSubdomainID(host)
	case AssetTypeIP:
		if ip != nil {
			return GenerateIPID(*ip)
		}
		return GenerateIPID(host)
	case AssetTypePort:
		if ip != nil && port != nil && protocol != nil {
			return GeneratePortID(*ip, *port, *protocol)
		}
	}
	// Fallback: generate based on all available info
	if port != nil && protocol != nil && ip != nil {
		return GeneratePortID(*ip, *port, *protocol)
	}
	if ip != nil {
		return GenerateIPID(*ip)
	}
	// Check if it's a subdomain (contains dots beyond TLD)
	if strings.Count(host, ".") > 1 {
		return GenerateSubdomainID(host)
	}
	return GenerateDomainID(host)
}
