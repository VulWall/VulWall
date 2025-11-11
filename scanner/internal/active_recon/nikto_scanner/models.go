package nikto_scanner

import "github.com/vulwall/scanners/internal/shared"

// ScanTarget is an alias for the shared ScanTarget model
// All active recon scanners use the same ScanTarget structure
type ScanTarget = shared.ScanTarget

// NiktoOutput represents the JSON output from Nikto scanner
// Nikto's JSON output format varies, this represents common fields
type NiktoOutput struct {
	Host          string          `json:"host"`
	IP            string          `json:"ip"`
	Port          string          `json:"port"`
	Vulnerabilities []NiktoVuln   `json:"vulnerabilities"`
	Statistics    NiktoStats      `json:"statistics,omitempty"`
}

// NiktoVuln represents a single vulnerability found by Nikto
type NiktoVuln struct {
	ID          string `json:"id"`          // Test ID from Nikto database
	Method      string `json:"method"`      // HTTP method used
	URL         string `json:"url"`         // Vulnerable URL/path
	Description string `json:"msg"`         // Vulnerability description
	References  string `json:"references,omitempty"` // External references (CVE, URLs, etc.)
}

// NiktoStats represents scan statistics
type NiktoStats struct {
	ElapsedTime  string `json:"elapsed"`
	ItemsTested  int    `json:"itemstested"`
	ItemsFound   int    `json:"itemsfound"`
}
