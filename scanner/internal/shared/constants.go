package shared

const (
	// Scan Status
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"

	// MongoDB Collections
	CollectionScanResults   = "scan_results"
	CollectionAttackSurface = "attack_surface"

	// Attack Surface Status
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"
)
