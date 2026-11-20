package certificate_scanner

import "time"

const (
	// findingSource is the source of every certificate finding and coverage record. It is
	// not "testssl": coverage is per (scan, source, discovery), so a testssl.sh run that
	// fails must not keep a renewed certificate's finding open, nor the reverse.
	findingSource = "certificate"

	// GroupCertificateScanner is the consumer group on domain_scan_triggers and
	// port_scan_triggers.
	GroupCertificateScanner = "certificate_scanner_service"

	// ConsumerBatchSize and ConsumerConcurrency: one check is a single TLS handshake.
	ConsumerBatchSize   = 10
	ConsumerConcurrency = 10

	// DefaultWarnDays and DefaultCriticalDays are the CERT_EXPIRY_WARN_DAYS and
	// CERT_EXPIRY_CRITICAL_DAYS defaults.
	DefaultWarnDays     = 30
	DefaultCriticalDays = 7

	// handshakeTimeout bounds the TCP connect and the TLS handshake of one check.
	handshakeTimeout = 15 * time.Second
)

// Finding identities. They stay the same while the condition holds (the day count is in the
// description), so a daily scan updates one finding instead of opening a new one. An
// expiring certificate that then expires gets the expired finding, and the expiring one is
// resolved by the coverage that no longer lists it.
const (
	findingTypeExpiring = "tls-certificate-expiring"
	findingTypeExpired  = "tls-certificate-expired"
	titleExpiring       = "TLS certificate expires soon: "
	titleExpired        = "TLS certificate expired: "
)

// tlsPorts are the open ports (port_scan_triggers) that speak TLS from the first byte and
// get the check by IP, without SNI. 443 is left out: its names are checked by hostname
// (domain_scan_triggers), the name the browser asks for. Ports that need STARTTLS (25, 587,
// 110, 143, ...) and service ports whose certificates are internal and rotated by the
// platform (Docker 2376, kubelet 10250) are left out too.
var tlsPorts = map[int]bool{
	465:  true, // SMTPS
	636:  true, // LDAPS
	993:  true, // IMAPS
	995:  true, // POP3S
	5986: true, // WinRM HTTPS
	6443: true, // Kubernetes API server
	8443: true, // HTTPS alt
}
