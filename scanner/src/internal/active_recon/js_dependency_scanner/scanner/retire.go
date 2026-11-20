package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/VulWall/VulWall/scanner/src/internal/core/execx"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

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

// ProcessedVulnerability represents a processed vulnerability ready for publishing
type ProcessedVulnerability struct {
	Component        string
	Version          string
	Severity         string
	Summary          string
	CVEs             []string
	CWEs             []string
	References       []string
	AffectedVersions string
	JSURL            string
	GitHubID         string
}

// RunRetireJS executes retire.js CLI and parses output
func RunRetireJS(ctx context.Context, scanPath string, logger *zap.Logger) (*RetireJSOutput, error) {
	// Run retire.js with JSON output
	cmd := execx.Command(ctx, "retire",
		"--path", scanPath,
		"--outputformat", "json",
		"--nocache",
		"--severity", "low", // Report all severities
	)

	output, err := cmd.CombinedOutput()

	// Parse JSON output regardless of exit code
	var result RetireJSOutput
	if len(output) > 0 {
		if parseErr := json.Unmarshal(output, &result); parseErr != nil {
			return nil, fmt.Errorf("failed to parse retire.js output: %w (output: %s)", parseErr, string(output))
		}
	}

	// Check if retire.js execution failed (but not exit code 13 which means vulnerabilities found)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 13 {
			logger.Debug("Vulnerabilities detected by retire.js")
		} else {
			return &result, fmt.Errorf("retire.js failed: %w", err)
		}
	}

	return &result, nil
}

// ProcessVulnerabilities converts retire.js output to processed vulnerabilities
func ProcessVulnerabilities(retireOutput *RetireJSOutput, fileMetadata []JSFileMetadata, targetURL string) []ProcessedVulnerability {
	// Create filename to URL mapping
	filenameToURL := make(map[string]string)
	for _, meta := range fileMetadata {
		filenameToURL[meta.Filename] = meta.URL
	}

	var vulnerabilities []ProcessedVulnerability

	for _, fileData := range retireOutput.Data {
		// Extract original JS URL from filename
		filename := filepath.Base(fileData.File)
		jsURL := filenameToURL[filename]
		if jsURL == "" {
			jsURL = targetURL // Fallback to page URL
		}

		for _, result := range fileData.Results {
			for _, vuln := range result.Vulnerabilities {
				pv := ProcessedVulnerability{
					Component:        result.Component,
					Version:          result.Version,
					Severity:         vuln.Severity,
					Summary:          vuln.Identifiers.Summary,
					CVEs:             vuln.Identifiers.CVE,
					CWEs:             vuln.CWE,
					References:       vuln.Info,
					AffectedVersions: formatAffectedVersions(vuln.Below, vuln.AtOrAbove),
					JSURL:            jsURL,
					GitHubID:         vuln.Identifiers.GitHubID,
				}

				vulnerabilities = append(vulnerabilities, pv)
			}
		}
	}

	return vulnerabilities
}

// formatAffectedVersions formats the version range string
func formatAffectedVersions(below, atOrAbove string) string {
	var parts []string
	if atOrAbove != "" {
		parts = append(parts, fmt.Sprintf(">= %s", atOrAbove))
	}
	if below != "" {
		parts = append(parts, fmt.Sprintf("< %s", below))
	}
	return strings.Join(parts, " && ")
}
