package knowledge_base

const (
	// GroupKBEngine is the consumer group for this service
	// Input stream: shared.StreamKBGenerationQueue (jobs published by findings_ingestion for new finding_types)
	GroupKBEngine = "knowledge_base_engine_service"

	// ConsumerBatchSize is the number of messages to process at a time
	// Keep at 1 due to API rate limits and high-quality generation time
	ConsumerBatchSize = 1
)
