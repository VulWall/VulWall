package shared

const (
	// Scan Types
	ScanTypePassiveRecon = "passive_recon"
	ScanTypeActiveRecon  = "active_recon"
	ScanTypeVulnScan     = "vuln_scan"
	ScanTypeReportGen    = "report_gen"

	// Scan Status
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"

	// Redis Stream Names
	StreamPassiveRecon  = "vulwall:passive_recon"
	StreamActiveRecon   = "vulwall:active_recon"
	StreamVulnScan      = "vulwall:vuln_scan"
	StreamReportGen     = "vulwall:report_gen"
	StreamAttackSurface = "vulwall:attack_surface"

	// Consumer Groups
	GroupPassiveRecon  = "passive_recon_group"
	GroupActiveRecon   = "active_recon_group"
	GroupVulnScan      = "vuln_scan_group"
	GroupReportGen     = "report_gen_group"
	GroupAttackSurface = "attack_surface_group"

	// MongoDB Collections
	CollectionScanJobs      = "scan_jobs"
	CollectionScanResults   = "scan_results"
	CollectionAttackSurface = "attack_surface"

	// Attack Surface Status
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"
)
