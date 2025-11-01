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

// GenerateDomainID creates a deterministic UUID for a domain scoped to an organization
// Same domain + org_id always produces the same ID
// Different orgs can have separate records for the same domain
func GenerateDomainID(orgID, domain string) string {
	// Normalize domain to lowercase
	normalized := strings.ToLower(strings.TrimSpace(domain))
	key := fmt.Sprintf("org:%s:domain:%s", orgID, normalized)
	return uuid.NewSHA1(DiscoveryNamespace, []byte(key)).String()
}

// GenerateSubdomainID creates a deterministic UUID for a subdomain scoped to an organization
// Same subdomain + org_id always produces the same ID
// Different orgs can have separate records for the same subdomain
func GenerateSubdomainID(orgID, subdomain string) string {
	// Normalize subdomain to lowercase
	normalized := strings.ToLower(strings.TrimSpace(subdomain))
	key := fmt.Sprintf("org:%s:subdomain:%s", orgID, normalized)
	return uuid.NewSHA1(DiscoveryNamespace, []byte(key)).String()
}

// GenerateIPID creates a deterministic UUID for an IP address scoped to an organization
// Same IP + org_id always produces the same ID
// Different orgs can have separate records for the same IP
func GenerateIPID(orgID, ip string) string {
	// Normalize IP (trim whitespace)
	normalized := strings.TrimSpace(ip)
	key := fmt.Sprintf("org:%s:ip:%s", orgID, normalized)
	return uuid.NewSHA1(DiscoveryNamespace, []byte(key)).String()
}

// GeneratePortID creates a deterministic UUID for a port on an IP scoped to an organization
// Protocol matters: 192.168.1.1:80/tcp != 192.168.1.1:80/udp
// Different orgs can have separate records for the same IP:port/protocol
func GeneratePortID(orgID, ip string, port int, protocol string) string {
	// Normalize inputs
	normalizedIP := strings.TrimSpace(ip)
	normalizedProto := strings.ToLower(strings.TrimSpace(protocol))

	// Format: org:orgID:port:ip:port/protocol
	key := fmt.Sprintf("org:%s:port:%s:%d/%s", orgID, normalizedIP, port, normalizedProto)
	return uuid.NewSHA1(DiscoveryNamespace, []byte(key)).String()
}

// GenerateDiscoveryID is a convenience function that generates the appropriate ID
// based on asset type. This is useful when you have all the information but aren't
// sure which specific function to call.
func GenerateDiscoveryID(orgID, assetType string, host string, ip *string, port *int, protocol *string) string {
	switch assetType {
	case AssetTypeDomain:
		return GenerateDomainID(orgID, host)
	case AssetTypeSubdomain:
		return GenerateSubdomainID(orgID, host)
	case AssetTypeIP:
		if ip != nil {
			return GenerateIPID(orgID, *ip)
		}
		return GenerateIPID(orgID, host)
	case AssetTypePort:
		if ip != nil && port != nil && protocol != nil {
			return GeneratePortID(orgID, *ip, *port, *protocol)
		}
	}
	// Fallback: generate based on all available info
	if port != nil && protocol != nil && ip != nil {
		return GeneratePortID(orgID, *ip, *port, *protocol)
	}
	if ip != nil {
		return GenerateIPID(orgID, *ip)
	}
	// Check if it's a subdomain (contains dots beyond TLD)
	if strings.Count(host, ".") > 1 {
		return GenerateSubdomainID(orgID, host)
	}
	return GenerateDomainID(orgID, host)
}
