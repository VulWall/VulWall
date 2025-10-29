package testssl_scanner

// TestSSLOutput represents the JSON output from testssl.sh scanner
// testssl.sh outputs JSON with metadata and a single scanResult object containing nested test arrays
type TestSSLOutput struct {
	Invocation string             `json:"Invocation,omitempty"` // Command invocation
	At         string             `json:"at,omitempty"`         // Hostname/OpenSSL path
	Version    string             `json:"version,omitempty"`    // testssl.sh version
	OpenSSL    string             `json:"openssl,omitempty"`    // OpenSSL version info
	StartTime  string             `json:"startTime,omitempty"`  // Unix timestamp (as string, testssl.sh is inconsistent)
	ScanResult []TestSSLScanResult `json:"scanResult"`           // Array with single scan result object
	ScanTime   int                `json:"scanTime,omitempty"`   // Total scan time in seconds
}

// TestSSLScanResult represents the scan result for a single target
// Contains nested arrays of different test types
type TestSSLScanResult struct {
	TargetHost     string             `json:"targetHost,omitempty"`
	IP             string             `json:"ip,omitempty"`
	Port           string             `json:"port,omitempty"`
	RDNS           string             `json:"rDNS,omitempty"`
	Service        string             `json:"service,omitempty"`
	Vulnerabilities []TestSSLFinding  `json:"vulnerabilities"`      // Security vulnerabilities - THIS is what we want!
	HeaderResponse  []TestSSLFinding  `json:"headerResponse"`       // HTTP header security issues
	Protocols      []TestSSLFinding  `json:"protocols,omitempty"`
	Ciphers        []TestSSLFinding  `json:"ciphers,omitempty"`
	// Other test categories we don't need for security findings
}

// TestSSLFinding represents a single finding from any test category
type TestSSLFinding struct {
	ID       string `json:"id"`                // Test ID (e.g., "BEAST", "POODLE", "heartbleed")
	Severity string `json:"severity"`          // OK, INFO, LOW, MEDIUM, HIGH, CRITICAL
	Finding  string `json:"finding"`           // Description of the finding
	CVE      string `json:"cve,omitempty"`     // CVE identifiers (space-separated)
	CWE      string `json:"cwe,omitempty"`     // CWE identifier
}

// ScanTarget represents a target to be scanned by testssl.sh
type ScanTarget struct {
	Target      string // Host:port to scan (e.g., "example.com:443")
	DiscoveryID string // Links back to Discovery._id
	TraceID     string
	OrgID       string
}
