package testssl_scanner

import "github.com/VulWall/VulWall/scanner/src/internal/shared"

// ScanTarget is an alias for the shared ScanTarget model
// All active recon scanners use the same ScanTarget structure
type ScanTarget = shared.ScanTarget

// TestSSLFinding represents a single finding from any test category
type TestSSLFinding struct {
	ID       string `json:"id"`                // Test ID (e.g., "BEAST", "POODLE", "heartbleed")
	Severity string `json:"severity"`          // OK, INFO, LOW, MEDIUM, HIGH, CRITICAL
	Finding  string `json:"finding"`           // Description of the finding
	CVE      string `json:"cve,omitempty"`     // CVE identifiers (space-separated)
	CWE      string `json:"cwe,omitempty"`     // CWE identifier
}
