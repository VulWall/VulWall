package nikto_scanner

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
	ID          string `json:"id"`          // OSVDB ID or custom ID
	Method      string `json:"method"`      // HTTP method used
	URL         string `json:"url"`         // Vulnerable URL/path
	Description string `json:"msg"`         // Vulnerability description
	References  string `json:"references,omitempty"` // External references
}

// NiktoStats represents scan statistics
type NiktoStats struct {
	ElapsedTime  string `json:"elapsed"`
	ItemsTested  int    `json:"itemstested"`
	ItemsFound   int    `json:"itemsfound"`
}

// ScanTarget represents a target to be scanned by Nikto
type ScanTarget struct {
	Target      string // URL or IP to scan
	DiscoveryID string // Links back to Discovery._id
	TraceID     string
	OrgID       string
}
