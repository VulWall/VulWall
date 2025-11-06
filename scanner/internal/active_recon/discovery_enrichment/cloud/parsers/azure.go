package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AzureParser parses Azure IP ranges from Microsoft download center
// URL: https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_YYYYMMDD.json
type AzureParser struct{}

// azureIPRangesResponse represents the Azure Service Tags JSON structure
type azureIPRangesResponse struct {
	ChangeNumber int    `json:"changeNumber"`
	Cloud        string `json:"cloud"`
	Values       []struct {
		Name       string `json:"name"`
		ID         string `json:"id"`
		Properties struct {
			ChangeNumber    int      `json:"changeNumber"`
			Region          string   `json:"region"`
			RegionID        int      `json:"regionId"`
			Platform        string   `json:"platform"`
			SystemService   string   `json:"systemService"`
			AddressPrefixes []string `json:"addressPrefixes"`
		} `json:"properties"`
	} `json:"values"`
}

// Parse parses Azure IP ranges JSON
func (p *AzureParser) Parse(data []byte) ([]IPRange, error) {
	var azureData azureIPRangesResponse
	if err := json.Unmarshal(data, &azureData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Azure JSON: %w", err)
	}

	var ranges []IPRange

	// Parse each service tag
	for _, value := range azureData.Values {
		region := normalizeAzureRegion(value.Properties.Region)
		service := normalizeAzureService(value.Properties.SystemService)

		// Parse each address prefix (CIDR)
		for _, cidr := range value.Properties.AddressPrefixes {
			// Skip empty CIDRs
			if cidr == "" {
				continue
			}

			ranges = append(ranges, IPRange{
				CIDR:     cidr,
				Provider: "Azure",
				Region:   region,
				Service:  service,
			})
		}
	}

	return ranges, nil
}

// GetProvider returns "Azure"
func (p *AzureParser) GetProvider() string {
	return "Azure"
}

// normalizeAzureRegion normalizes Azure region names
func normalizeAzureRegion(region string) string {
	// Azure uses region names like "eastus", "westeurope", "" (empty for global)
	region = strings.TrimSpace(region)
	if region == "" {
		return "global"
	}
	return strings.ToLower(region)
}

// normalizeAzureService normalizes Azure service names
func normalizeAzureService(service string) string {
	// Azure uses service names like "ActionGroup", "AzureCloud", "Storage"
	service = strings.TrimSpace(service)
	if service == "" {
		return ""
	}
	// Convert to uppercase for consistency
	return strings.ToUpper(service)
}
