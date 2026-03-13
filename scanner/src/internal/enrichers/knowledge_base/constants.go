package knowledge_base

import "time"

const (
	// GroupKBEngine is the consumer group for this service
	// Input stream: shared.StreamKBGenerationQueue (jobs published by findings_ingestion for new finding_types)
	GroupKBEngine = "knowledge_base_engine_service"

	// ConsumerBatchSize is the number of messages to process at a time
	// Keep at 1 due to API rate limits and high-quality generation time
	ConsumerBatchSize = 1

	// PostGenerationCooldown is the delay after a successful KB generation before
	// processing the next job. A single request with web search uses 25-80K input
	// tokens, which exceeds the Tier 1 rate limit of 30K input tokens/min. Without
	// this cooldown, the next request immediately hits a 429 and burns through
	// retries waiting for the per-minute window to reset.
	PostGenerationCooldown = 90 * time.Second
)
