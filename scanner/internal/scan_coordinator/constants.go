package scan_coordinator

import "time"

const (
	// SchedulerInterval defines how often the coordinator checks for scans to trigger
	SchedulerInterval = 1 * time.Hour

	// ScanMonitorInterval defines how often the scan monitor checks for completed scans
	ScanMonitorInterval = 15 * time.Minute
)
