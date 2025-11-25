package domain_ingestion

const (
	// Consumer group for domain ingestion
	// Input stream: shared.StreamDomainDiscoveryResults
	GroupDomainIngestion = "domain_ingestion_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) for consistent MongoDB writes
	ConsumerBatchSize = 1
)
