package domain_discovery

const (
	// Shodan subdomain discovery service consumer group
	// Input stream: shared.StreamDomainDiscoveryQueue
	// Output stream: shared.StreamDomainDiscoveryResults
	GroupShodanSubdomainService = "shodan_subdomain_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because Shodan API calls are rate-limited
	ConsumerBatchSize = 1
)
