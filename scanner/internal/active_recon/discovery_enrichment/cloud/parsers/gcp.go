package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GCPParser parses GCP IP ranges from https://www.gstatic.com/ipranges/cloud.json
type GCPParser struct{}

// gcpIPRangesResponse represents the GCP IP ranges JSON structure
type gcpIPRangesResponse struct {
	SyncToken    string `json:"syncToken"`
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4Prefix string `json:"ipv4Prefix,omitempty"`
		IPv6Prefix string `json:"ipv6Prefix,omitempty"`
		Service    string `json:"service"`
		Scope      string `json:"scope"`
	} `json:"prefixes"`
}

// Parse parses GCP IP ranges JSON
func (p *GCPParser) Parse(data []byte) ([]IPRange, error) {
	var gcpData gcpIPRangesResponse
	if err := json.Unmarshal(data, &gcpData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GCP JSON: %w", err)
	}

	var ranges []IPRange

	// Parse each prefix
	for _, prefix := range gcpData.Prefixes {
		// Determine CIDR (IPv4 or IPv6)
		cidr := ""
		if prefix.IPv4Prefix != "" {
			cidr = prefix.IPv4Prefix
		} else if prefix.IPv6Prefix != "" {
			cidr = prefix.IPv6Prefix
		}

		// Skip if no CIDR found
		if cidr == "" {
			continue
		}

		ranges = append(ranges, IPRange{
			CIDR:     cidr,
			Provider: "GCP",
			Region:   normalizeGCPRegion(prefix.Scope),
			Service:  normalizeGCPService(prefix.Service),
		})
	}

	return ranges, nil
}

// GetProvider returns "GCP"
func (p *GCPParser) GetProvider() string {
	return "GCP"
}

// normalizeGCPRegion normalizes GCP region/scope names
func normalizeGCPRegion(scope string) string {
	// GCP uses scope like "us-central1", "asia-northeast1", "global"
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return "unknown"
	}
	return strings.ToLower(scope)
}

// normalizeGCPService normalizes GCP service names
func normalizeGCPService(service string) string {
	// GCP uses service names like "Google Cloud", "Google Cloud Platform"
	service = strings.TrimSpace(service)
	if service == "" {
		return ""
	}

	// Simplify common service names
	switch strings.ToLower(service) {
	case "google cloud", "google cloud platform":
		return "GCP"
	default:
		return strings.ToUpper(service)
	}
}
