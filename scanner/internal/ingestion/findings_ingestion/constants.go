package findings_ingestion

const (
	// Consumer group for findings ingestion service
	GroupFindingsIngestion = "findings_ingestion_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) for consistent MongoDB writes
	ConsumerBatchSize = 1
)
