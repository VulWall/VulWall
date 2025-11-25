package audit_ingestion

const (
	// GroupAuditIngestion is the consumer group for system audit event ingestion
	// Input stream: shared.StreamSystemAuditLogs
	GroupAuditIngestion = "audit_ingestion_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) for consistent MongoDB writes
	ConsumerBatchSize = 1
)
