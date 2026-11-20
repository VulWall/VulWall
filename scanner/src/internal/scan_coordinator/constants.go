package scan_coordinator

import "time"

const (
	// ScanMonitorInterval defines how often the scan monitor checks for completed scans
	ScanMonitorInterval = 5 * time.Minute

	// QueuedScanPollInterval defines how often the coordinator looks for scans
	// that the web UI queued.
	QueuedScanPollInterval = 5 * time.Second

	// markFailedTimeout bounds the detached write that closes a scan which
	// failed to start (see Service.markFailed).
	markFailedTimeout = 10 * time.Second

	// QueuedScanBatchSize caps how many queued scans one poll reads.
	QueuedScanBatchSize = 100

	// Scan completion thresholds
	// ScanSafetyTimeout is the absolute upper bound for scan duration.
	// Scans exceeding this are force-completed and finding resolution is skipped.
	ScanSafetyTimeout = 3 * time.Hour

	// ScanIdleTimeout marks a scan as done if no ingestion activity has occurred
	// for this duration and no watched group holds work in flight (see
	// ScanStuckThreshold). Default; SCAN_IDLE_TIMEOUT overrides it.
	ScanIdleTimeout = 15 * time.Minute

	// ScanMinRuntime is the minimum scan age before idle detection applies.
	// Prevents premature completion of scans that haven't had time to produce results.
	// Default; SCAN_MIN_RUNTIME overrides it.
	ScanMinRuntime = 10 * time.Minute

	// ScanStuckThreshold is how long a pending entry may go without delivery before the
	// scan monitor stops treating it as work in flight. A watched group whose youngest
	// pending entry was delivered less than this ago blocks the idle timeout; older
	// entries are treated as stuck, and the idle timeout may close the scan. A single
	// job that legitimately runs longer than this is also treated as stuck.
	ScanStuckThreshold = 30 * time.Minute

	// ScanSettleGrace is how long ingestion activity must have been quiet before a
	// "pipeline drained" reading is trusted to mean the scan is done. It is larger than
	// the ingestion activity-write throttle (ActivityUpdateInterval, 30s) so a scan that
	// is merely between throttled activity writes is not misread as settled.
	ScanSettleGrace = 90 * time.Second

	// RefreshCron defines how often the scheduler reloads organizations from MongoDB, so a
	// schedule changed in the web app takes effect within 5 minutes.
	RefreshCron = "*/5 * * * *"

	// StreamCleanupCron defines how often the stream cleaner trims fully-processed messages.
	// Every 6 hours, at minute 5.
	StreamCleanupCron = "5 */6 * * *"
)
