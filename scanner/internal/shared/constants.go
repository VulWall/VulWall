package shared

const (
	// Ingestion Consumer Batch Size
	// Higher value for faster ingestion - MongoDB writes are fast
	IngestionBatchSize = 10

	// Scan Status
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"

	// Scan Type
	ScanTypeManual    = "manual"
	ScanTypeScheduled = "scheduled"
	ScanTypeOnDemand  = "on_demand"

	// MongoDB Collections
	CollectionAssets        = "assets"        // User-added assets to be scanned
	CollectionOrganizations = "organizations" // Organizations with subscription settings
	CollectionScans         = "scans"         // Scan execution records
	CollectionScanResults   = "scan_results"
	CollectionDiscoveries   = "discoveries" // Org-scoped asset registry (domains, subdomains, IPs, ports)
	CollectionFindings      = "findings"    // Security findings from scanning tools

	// Redis Streams - Domain Discovery
	StreamDomainDiscoveryQueue   = "domain_discovery_queue"   // Input stream for domain discovery jobs
	StreamDomainDiscoveryResults = "domain_discovery_results" // Output stream for domain discovery findings (consumed by ingestion service)

	// Redis Streams - IP/Port Discovery
	StreamIPDiscoveryQueue   = "ip_discovery_queue"   // Input stream for IP port discovery jobs
	StreamIPDiscoveryResults = "ip_discovery_results" // Output stream for IP port discovery findings (consumed by ingestion service)

	// Redis Streams - Security Findings
	StreamSecurityFindings = "security_findings" // Output stream for security findings from scanning tools (consumed by findings ingestion)

	// Redis Streams - Discovery Enrichment
	StreamDiscoveryEnrichmentQueue   = "discovery_enrichment_queue"   // Input stream for enrichment jobs (published by ingestion services)
	StreamDiscoveryEnrichmentResults = "discovery_enrichment_results" // Output stream for discovery enrichment data (consumed by enrichment ingestion)

	// Redis Streams - Active Scan Triggers (published by ingestion services AFTER persisting discoveries)
	StreamDomainScanTriggers = "domain_scan_triggers" // Triggers for active recon scanners on domains/subdomains (published by domain_ingestion)
	StreamPortScanTriggers   = "port_scan_triggers"   // Triggers for active recon scanners on ports (published by port_ingestion)

	// Redis Streams - System Audit Logs
	StreamSystemAuditLogs = "system_audit_logs" // System-level audit events (template updates, service events, etc.)

	// MongoDB Collections - Audit
	CollectionAuditLogs = "audit_logs" // Existing audit logs collection (shared with Dashboard)

	// Asset Types (for Discovery.AssetType)
	AssetTypeDomain    = "domain"
	AssetTypeSubdomain = "subdomain"
	AssetTypeIP        = "ip"
	AssetTypePort      = "port"

	// Discovery Asset Status (technical state)
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"

	// Ownership Status (organizational state)
	OwnershipStatusVerified = "verified" // Asset verified to belong to org
	OwnershipStatusNotMine  = "NotMine"  // Asset does not belong to org
	OwnershipStatusNotSure  = "NotSure"  // Asset ownership unclear/pending verification

	// Protocol constants
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolSCTP = "sctp"
	ProtocolICMP = "icmp"

	// Discovery target type constants
	TargetTypeDomain = "domain"
	TargetTypeIP     = "ip"
	TargetTypeCIDR   = "cidr"

	// Finding Severity Levels
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"

	// Finding Status
	FindingStatusOpen     = "open"
	FindingStatusResolved = "resolved"

	// HTTP User Agent (shared across all scanners)
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
)
