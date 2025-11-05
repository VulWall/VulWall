package waf_detector

// DetectionTarget represents a target for WAF detection
type DetectionTarget struct {
	TargetURL   string  // URL to probe (e.g., "https://example.com")
	DiscoveryID string  // Links back to Discovery._id
	TraceID     string  // Request tracing
	ScanID      *string // Optional: scan identifier for linking to UI scans
	OrgID       string  // Organization GUID
}
