package webtechprofiler

// ScanTarget represents a target to be scanned by WebTechProfiler
type ScanTarget struct {
	Target      string  // URL or IP to scan
	DiscoveryID string  // Links back to Discovery._id
	TraceID     string  // Request tracing ID
	ScanID      *string // Optional: scan identifier for linking to UI scans
	OrgID       string  // Organization GUID
}

// TechDetection represents a detected technology
type TechDetection struct {
	Technology string // Name of the detected technology
	URL        string // URL where technology was detected
}
