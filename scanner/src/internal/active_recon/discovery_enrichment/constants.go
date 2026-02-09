package discovery_enrichment

const (
	// Consumer group for discovery enrichment service (discovery_enrichment_queue)
	GroupDiscoveryEnrichment = "discovery_enrichment_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because WAF detection + geolocation involves HTTP probes
	ConsumerBatchSize = 1
)
