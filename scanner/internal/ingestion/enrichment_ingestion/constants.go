package enrichment_ingestion

const (
	// Consumer group for enrichment ingestion
	// Input stream: shared.StreamAssetEnrichmentResults
	GroupEnrichmentIngestion = "enrichment_ingestion_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) for consistent MongoDB writes
	ConsumerBatchSize = 1
)
