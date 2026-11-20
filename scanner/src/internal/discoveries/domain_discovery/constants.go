package domain_discovery

const (
	// GroupDomainDiscovery is the domain discovery consumer group (subfinder + DNS resolution).
	// Input stream: shared.StreamDomainDiscoveryQueue
	// Output stream: shared.StreamDomainDiscoveryResults
	GroupDomainDiscovery = "domain_discovery_service"

	// legacyGroup is the name GroupDomainDiscovery had before it was renamed.
	// DropLegacyGroup removes it at startup.
	legacyGroup = "shodan_subdomain_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because subfinder enumeration is run serially per job
	ConsumerBatchSize = 1
)
