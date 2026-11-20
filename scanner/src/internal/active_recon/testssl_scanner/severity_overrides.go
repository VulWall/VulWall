package testssl_scanner

import "github.com/VulWall/VulWall/scanner/src/internal/shared"

// severityOverrides re-rates specific testssl.sh findings where the generic
// severity from testssl.sh doesn't match real-world exploitability.
//
// Applied in convertToSecurityFinding() after the initial mapSeverity() translation.
var severityOverrides = map[string]string{
	"BREACH":         shared.SeverityLow,  // Requires compression + secrets + attacker input — theoretical
	"BEAST_CBC_TLS1": shared.SeverityLow,  // Mitigated by TLSv1.1+ ("likely mitigated")
	"LUCKY13":        shared.SeverityInfo, // Sub-microsecond timing attack, academic only
	"SWEET32":        shared.SeverityInfo, // Requires ~32GB ciphertext under same key, infeasible
	"CRIME_TLS":      shared.SeverityInfo, // All browsers disabled TLS compression since 2012
}
