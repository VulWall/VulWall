package scan_coordinator

import "time"

const (
	// ScanMonitorInterval defines how often the scan monitor checks for completed scans
	ScanMonitorInterval = 15 * time.Minute

	// RefreshCron defines how often the scheduler reloads organizations from MongoDB.
	// Standard 5-field cron: every hour at minute 0.
	RefreshCron = "0 * * * *"
)
