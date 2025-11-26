package ai_finding_enricher

const (
	// GroupAIFindingEnricher is the consumer group for this service
	// Input stream: shared.StreamSecurityFindings
	GroupAIFindingEnricher = "ai_finding_enricher_service"

	// ConsumerBatchSize is the number of messages to process at a time
	// Keep low due to API rate limits and processing time
	ConsumerBatchSize = 1
)

// AllowedSeverities defines which severity levels trigger AI enrichment
// Extensible: add/remove severities as needed
var AllowedSeverities = map[string]bool{
	"critical": true,
	"high":     true,
}
