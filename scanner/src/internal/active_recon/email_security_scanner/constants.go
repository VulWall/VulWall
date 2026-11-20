package email_security_scanner

const (
	// findingSource is the source of every email security finding and coverage record.
	findingSource = "email-security"

	// GroupEmailSecurityScanner is the consumer group name for the email_security_scanner service
	// Listens to domain_scan_triggers stream only (domains and subdomains)
	GroupEmailSecurityScanner = "email_security_scanner_service"

	// ConsumerBatchSize is the number of messages to read at a time
	// DNS lookups are fast, so we process in batches of 10
	ConsumerBatchSize = 10
)
