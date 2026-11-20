package shared

const (
	// Ingestion Consumer Batch Size
	// Higher value for faster ingestion - MongoDB writes are fast
	IngestionBatchSize = 10

	// Scan Status
	// StatusQueued is written by the web UI when a user requests a scan. The
	// scan coordinator claims queued scans and moves them to running.
	StatusQueued  = "queued"
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"

	// ScanReasonInterruptedByRestart is the status_reason of a scan that was
	// pending or running when the scanner stopped. Its pipeline state was lost,
	// so the scan is closed as failed and its findings are left untouched.
	ScanReasonInterruptedByRestart = "interrupted_by_restart"

	// Scan completion reasons, stored in scans.completion_reason. Only a
	// pipeline_quiescent close can reconcile findings (resolve the ones the
	// scan did not see again); every other close leaves findings untouched.
	ScanCompletionPipelineQuiescent = "pipeline_quiescent"
	ScanCompletionIdleTimeout       = "idle_timeout"
	ScanCompletionSafetyTimeout     = "safety_timeout"

	// Reasons in scans.degraded_assets[].reason: domain discovery could not see
	// the whole attack surface of one root domain asset. The scan still resolves
	// findings of every other asset; the findings under a degraded root stay open.
	//
	// ScanDegradedDNSFailures: the resolver failed for the root domain, or for
	// too many of its subdomains.
	ScanDegradedDNSFailures = "dns_failures"
	// ScanDegradedRootNXDOMAIN: the root domain does not exist (NXDOMAIN),
	// confirmed by public resolvers.
	ScanDegradedRootNXDOMAIN = "root_nxdomain"
	// ScanDegradedSubdomainEnumFailed: subdomain enumeration (subfinder) failed.
	ScanDegradedSubdomainEnumFailed = "subdomain_enumeration_failed"

	// Scan Type
	ScanTypeScheduled = "scheduled"
	ScanTypeRequested = "requested"

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

	// Redis Streams - Knowledge Base Generation
	StreamKBGenerationQueue   = "kb_generation_queue"   // Input stream for KB generation jobs (published by findings_ingestion for new finding_types)
	StreamKBGenerationResults = "kb_generation_results" // Output stream for KB entries (consumed by kb_ingestion)

	// MongoDB Collections - Knowledge Base
	CollectionKnowledgeBase = "knowledge_base" // Shared KB entries keyed by finding_type (one entry per unique finding_type)

	// Redis Streams - Active Scan Triggers (published by ingestion services AFTER persisting discoveries)
	StreamDomainScanTriggers = "domain_scan_triggers" // Triggers for active recon scanners on domains/subdomains (published by domain_ingestion)
	StreamPortScanTriggers   = "port_scan_triggers"   // Triggers for active recon scanners on ports (published by port_ingestion)

	// Redis Streams - Dead Letter
	StreamDeadLetter = "dead_letter" // Messages that failed processing permanently (poison messages)

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
