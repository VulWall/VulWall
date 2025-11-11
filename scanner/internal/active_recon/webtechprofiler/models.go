package webtechprofiler

import (
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/vulwall/scanners/internal/shared"
)

// ScanTarget is an alias for the shared ScanTarget model
// All active recon scanners use the same ScanTarget structure
type ScanTarget = shared.ScanTarget

// TechDetectionWithInfo represents a detected technology with detailed information
type TechDetectionWithInfo struct {
	Technology string              // Name of the detected technology
	URL        string              // URL where technology was detected
	AppInfo    wappalyzer.AppInfo  // Detailed information from Wappalyzer
}
