package scan_coordinator

import "time"

const (
	// ScanMonitorInterval defines how often the scan monitor checks for completed scans
	ScanMonitorInterval = 5 * time.Minute

	// Scan completion thresholds
	// ScanSafetyTimeout is the absolute upper bound for scan duration.
	// Scans exceeding this are force-completed and finding resolution is skipped.
	ScanSafetyTimeout = 3 * time.Hour

	// ScanIdleTimeout marks a scan as done if no ingestion activity has occurred
	// for this duration. Safe to resolve findings because ingestion has settled.
	ScanIdleTimeout = 15 * time.Minute

	// ScanMinRuntime is the minimum scan age before idle detection applies.
	// Prevents premature completion of scans that haven't had time to produce results.
	ScanMinRuntime = 10 * time.Minute

	// RefreshCron defines how often the scheduler reloads organizations from MongoDB.
	// Standard 5-field cron: every hour at minute 0.
	RefreshCron = "0 * * * *"

	// StreamCleanupCron defines how often the stream cleaner trims fully-processed messages.
	// Every 6 hours (at minute 5, offset from org refresh at minute 0).
	StreamCleanupCron = "5 */6 * * *"
)
