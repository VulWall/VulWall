package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AWSParser parses AWS IP ranges from https://ip-ranges.amazonaws.com/ip-ranges.json
type AWSParser struct{}

// awsIPRangesResponse represents the AWS IP ranges JSON structure
type awsIPRangesResponse struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix         string `json:"ipv6_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"ipv6_prefixes"`
}

// Parse parses AWS IP ranges JSON
func (p *AWSParser) Parse(data []byte) ([]IPRange, error) {
	var awsData awsIPRangesResponse
	if err := json.Unmarshal(data, &awsData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AWS JSON: %w", err)
	}

	var ranges []IPRange

	// Parse IPv4 prefixes
	for _, prefix := range awsData.Prefixes {
		// Skip entries without CIDR
		if prefix.IPPrefix == "" {
			continue
		}

		ranges = append(ranges, IPRange{
			CIDR:     prefix.IPPrefix,
			Provider: "AWS",
			Region:   normalizeAWSRegion(prefix.Region),
			Service:  normalizeAWSService(prefix.Service),
		})
	}

	// Parse IPv6 prefixes
	for _, prefix := range awsData.IPv6Prefixes {
		// Skip entries without CIDR
		if prefix.IPv6Prefix == "" {
			continue
		}

		ranges = append(ranges, IPRange{
			CIDR:     prefix.IPv6Prefix,
			Provider: "AWS",
			Region:   normalizeAWSRegion(prefix.Region),
			Service:  normalizeAWSService(prefix.IPv6Prefix),
		})
	}

	return ranges, nil
}

// GetProvider returns "AWS"
func (p *AWSParser) GetProvider() string {
	return "AWS"
}

// normalizeAWSRegion normalizes AWS region names
func normalizeAWSRegion(region string) string {
	// AWS uses region names like "us-east-1", "GLOBAL", "ap-northeast-1"
	region = strings.TrimSpace(region)
	if region == "" {
		return "unknown"
	}
	return strings.ToLower(region)
}

// normalizeAWSService normalizes AWS service names
func normalizeAWSService(service string) string {
	// AWS uses service names like "AMAZON", "EC2", "S3", "CLOUDFRONT"
	service = strings.TrimSpace(service)
	if service == "" {
		return ""
	}
	// Keep common service names capitalized for consistency
	return strings.ToUpper(service)
}
