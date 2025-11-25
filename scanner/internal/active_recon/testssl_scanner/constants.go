package testssl_scanner

const (
	// Consumer group for testssl scanner service
	// Listens to both domain_discovery_results and ip_discovery_results
	GroupTestSSLScanner = "testssl_scanner_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because TestSSL scans are slow
	ConsumerBatchSize = 1
)
