package testssl_scanner

const (
	// Consumer group for testssl scanner service
	// Listens to domain_scan_triggers for TLS/SSL analysis
	GroupTestSSLScanner = "testssl_scanner_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because TestSSL scans are slow
	ConsumerBatchSize = 1
)
