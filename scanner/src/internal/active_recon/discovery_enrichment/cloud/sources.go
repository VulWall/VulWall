package cloud

import "github.com/vulwall/scanners/internal/active_recon/discovery_enrichment/cloud/parsers"

// CloudSource defines a cloud provider IP range source
type CloudSource struct {
	Name     string          // Provider name (e.g., "AWS", "Azure", "GCP")
	URL      string          // JSON file URL
	Parser   parsers.Parser  // Provider-specific parser
	Enabled  bool            // Enable/disable per provider
	FileName string          // Local cache filename (e.g., "aws.json")
}

// GetDefaultCloudSources returns the default cloud provider sources
func GetDefaultCloudSources() []CloudSource {
	return []CloudSource{
		{
			Name:     "AWS",
			URL:      "https://ip-ranges.amazonaws.com/ip-ranges.json",
			Parser:   &parsers.AWSParser{},
			Enabled:  true,
			FileName: "aws.json",
		},
		{
			Name:     "Azure",
			URL:      "https://azureipranges.azurewebsites.net/getPrefixes/Public/AzureCloud",
			Parser:   &parsers.AzureParser{},
			Enabled:  true,
			FileName: "azure.json",
		},
		{
			Name:     "GCP",
			URL:      "https://www.gstatic.com/ipranges/cloud.json",
			Parser:   &parsers.GCPParser{},
			Enabled:  true,
			FileName: "gcp.json",
		},
		{
			Name:     "Fastly",
			URL:      "https://api.fastly.com/public-ip-list",
			Parser:   &parsers.FastlyParser{},
			Enabled:  true,
			FileName: "fastly.json",
		},
		// Future providers can be added here:
		// {
		//     Name:     "Oracle",
		//     URL:      "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
		//     Parser:   &parsers.OracleParser{},
		//     Enabled:  false,
		//     FileName: "oracle.json",
		// },
		// {
		//     Name:     "DigitalOcean",
		//     URL:      "https://digitalocean.com/geo/google.csv",
		//     Parser:   &parsers.DigitalOceanParser{},
		//     Enabled:  false,
		//     FileName: "digitalocean.json",
		// },
	}
}
