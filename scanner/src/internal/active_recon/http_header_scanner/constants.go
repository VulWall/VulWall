package http_header_scanner

const (
	// findingSource is the source of every header finding and coverage record.
	findingSource = "http-headers"

	// GroupHTTPHeaderScanner is the consumer group name for the http_header_scanner service
	// Listens to domain_scan_triggers stream only (domains and subdomains)
	GroupHTTPHeaderScanner = "http_header_scanner_service"

	// ConsumerBatchSize is the number of messages to read at a time
	ConsumerBatchSize = 10
)
