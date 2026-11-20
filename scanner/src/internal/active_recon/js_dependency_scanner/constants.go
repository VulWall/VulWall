package js_dependency_scanner

const (
	// findingSource is the source of every JS dependency finding and coverage record.
	findingSource = "jsscanner"

	// GroupJSDependencyScanner is the consumer group name for the js_dependency_scanner service
	// Listens to domain_discovery_results stream only (domains and subdomains)
	GroupJSDependencyScanner = "js_dependency_scanner_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Higher value (10) because JS scanning uses parallel downloads
	ConsumerBatchSize = 10
)
