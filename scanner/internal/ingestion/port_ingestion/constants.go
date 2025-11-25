package port_ingestion

const (
	// Consumer group for port ingestion
	// Input stream: shared.StreamIPDiscoveryResults
	GroupPortIngestion = "port_ingestion_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) for consistent MongoDB writes
	ConsumerBatchSize = 1
)
