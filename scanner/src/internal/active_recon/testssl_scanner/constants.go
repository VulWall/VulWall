package testssl_scanner

const (
	// findingSource is the source of every testssl finding and coverage record.
	findingSource = "testssl"

	// Consumer group for testssl scanner service
	// Listens to domain_scan_triggers for TLS/SSL analysis
	GroupTestSSLScanner = "testssl_scanner_service"

	// DefaultConcurrency is the number of concurrent testssl.sh worker goroutines.
	// Each worker processes one domain at a time. Override via TESTSSL_CONCURRENCY env var.
	DefaultConcurrency = 5
)
