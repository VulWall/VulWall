package parsers

import (
	"encoding/json"
	"fmt"
)

// FastlyParser parses Fastly IP ranges from https://api.fastly.com/public-ip-list
type FastlyParser struct{}

// fastlyIPRangesResponse represents the Fastly API JSON structure
type fastlyIPRangesResponse struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
}

// Parse parses Fastly IP ranges JSON
func (p *FastlyParser) Parse(data []byte) ([]IPRange, error) {
	var fastlyData fastlyIPRangesResponse
	if err := json.Unmarshal(data, &fastlyData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Fastly JSON: %w", err)
	}

	var ranges []IPRange

	// Parse IPv4 addresses
	for _, cidr := range fastlyData.Addresses {
		if cidr == "" {
			continue
		}

		ranges = append(ranges, IPRange{
			CIDR:     cidr,
			Provider: "Fastly",
			Region:   "global", // Fastly is a global CDN
			Service:  "CDN",
		})
	}

	// Parse IPv6 addresses
	for _, cidr := range fastlyData.IPv6Addresses {
		if cidr == "" {
			continue
		}

		ranges = append(ranges, IPRange{
			CIDR:     cidr,
			Provider: "Fastly",
			Region:   "global",
			Service:  "CDN",
		})
	}

	return ranges, nil
}

// GetProvider returns "Fastly"
func (p *FastlyParser) GetProvider() string {
	return "Fastly"
}
