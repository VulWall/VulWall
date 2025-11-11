package nuclei_scanner

import "github.com/vulwall/scanners/internal/shared"

// ScanTarget is an alias for the shared ScanTarget model
// All active recon scanners use the same ScanTarget structure
type ScanTarget = shared.ScanTarget

// NucleiOutput represents the JSON output from Nuclei scanner
type NucleiOutput struct {
	TemplateID   string                 `json:"template-id"`
	TemplatePath string                 `json:"template-path"`
	Info         NucleiInfo             `json:"info"`
	Type         string                 `json:"type"`
	Host         string                 `json:"host"`
	MatchedAt    string                 `json:"matched-at"`
	ExtractedResults []string           `json:"extracted-results,omitempty"`
	Timestamp    string                 `json:"timestamp"`
	CurlCommand  string                 `json:"curl-command,omitempty"`
	MatcherName  string                 `json:"matcher-name,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// NucleiInfo represents the info section of Nuclei output
type NucleiInfo struct {
	Name        string              `json:"name"`
	Author      []string            `json:"author"`
	Tags        []string            `json:"tags"`
	Description string              `json:"description"`
	Reference   []string            `json:"reference,omitempty"`
	Severity    string              `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
