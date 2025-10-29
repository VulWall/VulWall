package testssl_scanner

// TestSSLOutput represents the JSON output from testssl.sh scanner
// testssl.sh outputs JSON with metadata and findings array
type TestSSLOutput struct {
	Invocation string           `json:"Invocation,omitempty"` // Command invocation
	At         string           `json:"at,omitempty"`         // Hostname/OpenSSL path
	Version    string           `json:"version,omitempty"`    // testssl.sh version
	OpenSSL    string           `json:"openssl,omitempty"`    // OpenSSL version info
	StartTime  int64            `json:"startTime,omitempty"`  // Unix timestamp
	ScanResult []TestSSLFinding `json:"scanResult"`           // Array of findings
}

// TestSSLFinding represents a single finding from testssl.sh
type TestSSLFinding struct {
	ID       string `json:"id"`       // Test ID (e.g., "cert_trust", "BEAST", "POODLE")
	IP       string `json:"ip"`       // Target IP
	Port     string `json:"port"`     // Target port
	Severity string `json:"severity"` // OK, LOW, MEDIUM, HIGH, CRITICAL
	Finding  string `json:"finding"`  // Description of the finding
	CWE      string `json:"cwe,omitempty"`
	CVE      string `json:"cve,omitempty"`
}

// ScanTarget represents a target to be scanned by testssl.sh
type ScanTarget struct {
	Target      string // Host:port to scan (e.g., "example.com:443")
	DiscoveryID string // Links back to Discovery._id
	TraceID     string
	OrgID       string
}
