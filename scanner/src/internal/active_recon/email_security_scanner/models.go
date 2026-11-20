package email_security_scanner

import "github.com/VulWall/VulWall/scanner/src/internal/shared"

// ScanTarget is an alias for the shared ScanTarget model
// All active recon scanners use the same ScanTarget structure
type ScanTarget = shared.ScanTarget

// EmailCheckResult represents the result of a single email security check
type EmailCheckResult struct {
	FindingType string
	Severity    string
	Title       string
	Description string
	Value       string // The actual DNS record value (if present)
	References  []string
}
