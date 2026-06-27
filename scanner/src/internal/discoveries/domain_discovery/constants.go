package domain_discovery

const (
	// Subdomain discovery service consumer group (subfinder-backed)
	// Input stream: shared.StreamDomainDiscoveryQueue
	// Output stream: shared.StreamDomainDiscoveryResults
	// NOTE: value "shodan_subdomain_service" is persisted in Redis and tracked by
	// scan_monitor downstream — do NOT change it.
	GroupShodanSubdomainService = "shodan_subdomain_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because subfinder enumeration is run serially per job
	ConsumerBatchSize = 1
)
