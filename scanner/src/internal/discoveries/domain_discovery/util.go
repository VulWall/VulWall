package domain_discovery

import (
	"strings"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// determineDomainAssetType determines if a hostname is a domain or subdomain
// This function is ONLY for domain/subdomain classification, not for IPs or ports
// Note: parentID in this context refers to the parent domain, indicating a subdomain relationship
func determineDomainAssetType(host string, parentID *string) string {
	// If parentID is specified, it's a subdomain under a parent domain
	if parentID != nil && *parentID != "" {
		return shared.AssetTypeSubdomain
	}

	// Count dots to determine if subdomain
	// example.com = 1 dot = domain
	// api.example.com = 2 dots = subdomain
	dotCount := strings.Count(host, ".")
	if dotCount > 1 {
		return shared.AssetTypeSubdomain
	}

	return shared.AssetTypeDomain
}
