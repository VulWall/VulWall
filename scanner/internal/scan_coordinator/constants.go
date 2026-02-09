package scan_coordinator

import "time"

const (
	// ScanMonitorInterval defines how often the scan monitor checks for completed scans
	ScanMonitorInterval = 15 * time.Minute

	// RefreshCron defines how often the scheduler reloads organizations from MongoDB.
	// Standard 5-field cron: every hour at minute 0.
	RefreshCron = "0 * * * *"

	// StreamCleanupCron defines how often the stream cleaner trims fully-processed messages.
	// Every 10 minutes (at minute 5, 15, 25, 35, 45, 55 — offset from org refresh at minute 0).
	StreamCleanupCron = "5/10 * * * *"
)
