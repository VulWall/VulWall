package nuclei_scanner

const (
	// Consumer group for Nuclei scanner service
	// Listens to both domain_discovery_results and ip_discovery_results
	GroupNucleiScanner = "nuclei_scanner_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// Keep low (1) because Nuclei scans are slow
	ConsumerBatchSize = 1

	// DefaultTemplateUpdateCron is the default cron schedule for template updates
	// Default: 2:00 AM UTC daily ("0 2 * * *")
	// Can be overridden with NUCLEI_TEMPLATE_UPDATE_CRON environment variable
	DefaultTemplateUpdateCron = "0 2 * * *"
)
