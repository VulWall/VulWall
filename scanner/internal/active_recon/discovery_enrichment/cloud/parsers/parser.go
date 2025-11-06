package parsers

// IPRange represents a parsed IP range with cloud provider metadata
type IPRange struct {
	CIDR     string // "3.5.140.0/22"
	Provider string // "AWS", "Azure", "GCP"
	Region   string // "us-east-1", "westus", "asia-northeast1"
	Service  string // "EC2", "S3", "COMPUTE", "STORAGE" (optional, may be empty)
}

// Parser defines the interface for provider-specific IP range parsers
type Parser interface {
	// Parse parses provider-specific JSON data and returns IP ranges
	Parse(data []byte) ([]IPRange, error)

	// GetProvider returns the provider name (e.g., "AWS", "Azure", "GCP")
	GetProvider() string
}
