package discovery_enrichment

// EnrichmentTarget represents a target for discovery enrichment (WAF detection + IP geolocation)
type EnrichmentTarget struct {
	DiscoveryID string  // Links back to Discovery._id
	AssetType   string  // Asset type (domain, subdomain, ip, port)
	TraceID     string  // Request tracing
	ScanID      *string // Optional: scan identifier for linking to UI scans
	OrgID       string  // Organization GUID
	Host        string  // Domain/subdomain name (for WAF detection)
	IP          string  // IP address (for geolocation)
}
