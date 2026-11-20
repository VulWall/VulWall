package nuclei_scanner

import "github.com/VulWall/VulWall/scanner/src/internal/shared"

// severityOverrides re-rates specific Nuclei template findings where the
// default severity doesn't match real-world exploitability.
//
// Applied in convertToSecurityFinding() after the initial mapSeverity() translation.
var severityOverrides = map[string]string{
	"expired-ssl":     shared.SeverityHigh,   // Broken trust chain, MITM possible, users click through warnings
	"self-signed-ssl": shared.SeverityMedium, // No chain of trust, may be intentional for internal
}
