package ai_finding_enricher

const (
	// GroupAIFindingEnricher is the consumer group for this service
	// Input stream: shared.StreamAIEnrichmentQueue (jobs pre-filtered by findings_ingestion)
	GroupAIFindingEnricher = "ai_finding_enricher_service"

	// ConsumerBatchSize is the number of messages to process at a time
	// Keep low due to API rate limits and processing time
	ConsumerBatchSize = 1
)
