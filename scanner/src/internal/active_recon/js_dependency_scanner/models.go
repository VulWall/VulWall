package js_dependency_scanner

import (
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// ScanTarget is an alias for the shared ScanTarget model
// All active recon scanners use the same ScanTarget structure
type ScanTarget = shared.ScanTarget

// RetireJSOutput represents the complete output from retire.js JSON format
type RetireJSOutput struct {
	Version  string           `json:"version"`
	Start    time.Time        `json:"start"`
	Data     []VulnerableFile `json:"data"`
	Messages []string         `json:"messages"`
	Errors   []string         `json:"errors"`
	Time     float64          `json:"time"`
}

// VulnerableFile represents a single file with detected vulnerabilities
type VulnerableFile struct {
	File    string            `json:"file"`
	Results []ComponentResult `json:"results"`
}

// ComponentResult represents detection results for a specific component
type ComponentResult struct {
	Version         string          `json:"version"`
	Component       string          `json:"component"`
	NPMName         string          `json:"npmname,omitempty"`
	Detection       string          `json:"detection"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Licenses        []string        `json:"licenses,omitempty"`
}

// Vulnerability represents a single vulnerability in a component
type Vulnerability struct {
	Info        []string                `json:"info"`
	Below       string                  `json:"below,omitempty"`
	AtOrAbove   string                  `json:"atOrAbove,omitempty"`
	Severity    string                  `json:"severity"`
	Identifiers VulnerabilityIdentifier `json:"identifiers"`
	CWE         []string                `json:"cwe,omitempty"`
}

// VulnerabilityIdentifier contains identifying information for a vulnerability
type VulnerabilityIdentifier struct {
	Summary  string   `json:"summary"`
	CVE      []string `json:"CVE,omitempty"`
	Issue    string   `json:"issue,omitempty"`
	Bug      string   `json:"bug,omitempty"`
	RetID    string   `json:"retid,omitempty"`
	GitHubID string   `json:"githubID,omitempty"`
	PR       string   `json:"PR,omitempty"`
}

// JSFileMetadata tracks information about a downloaded JavaScript file
type JSFileMetadata struct {
	URL      string // Original URL
	Filename string // Local filename
}
