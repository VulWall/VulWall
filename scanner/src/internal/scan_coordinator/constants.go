package scan_coordinator

import "time"

const (
	// ScanMonitorInterval defines how often the scan monitor checks for completed scans
	ScanMonitorInterval = 5 * time.Minute

	// RefreshCron defines how often the scheduler reloads organizations from MongoDB.
	// Standard 5-field cron: every hour at minute 0.
	RefreshCron = "0 * * * *"

	// StreamCleanupCron defines how often the stream cleaner trims fully-processed messages.
	// Every 6 hours (at minute 5, offset from org refresh at minute 0).
	StreamCleanupCron = "5 */6 * * *"
)
