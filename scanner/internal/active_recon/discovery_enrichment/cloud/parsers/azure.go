package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AzureParser parses Azure IP ranges from multiple sources
// Supports both Microsoft format and azureipranges.azurewebsites.net format
type AzureParser struct{}

// azureIPRangesResponse represents the Microsoft Azure Service Tags JSON structure
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

// azureWebsiteResponse represents the azureipranges.azurewebsites.net JSON structure (array format)
type azureWebsiteResponse []struct {
	ChangeNumber    int      `json:"changeNumber"`
	Region          string   `json:"region"`
	Platform        string   `json:"platform"`
	SystemService   string   `json:"systemService"`
	AddressPrefixes []string `json:"addressPrefixes"`
}

// Parse parses Azure IP ranges JSON (supports both formats)
func (p *AzureParser) Parse(data []byte) ([]IPRange, error) {
	var ranges []IPRange

	// Try parsing as array format first (azureipranges.azurewebsites.net)
	var websiteData azureWebsiteResponse
	if err := json.Unmarshal(data, &websiteData); err == nil && len(websiteData) > 0 {
		// Successfully parsed as array format
		for _, item := range websiteData {
			region := normalizeAzureRegion(item.Region)
			service := normalizeAzureService(item.SystemService)

			for _, cidr := range item.AddressPrefixes {
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

	// Try parsing as Microsoft format (with "values" wrapper)
	var msData azureIPRangesResponse
	if err := json.Unmarshal(data, &msData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Azure JSON (tried both formats): %w", err)
	}

	// Parse each service tag
	for _, value := range msData.Values {
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
