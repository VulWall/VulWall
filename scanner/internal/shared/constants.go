package shared

const (
	// Scan Status
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"

	// MongoDB Collections
	CollectionScanResults = "scan_results"
	CollectionDiscoveries = "discoveries" // Org-scoped asset registry (domains, subdomains, IPs, ports)
	CollectionFindings    = "findings"    // Security findings from scanning tools

	// Redis Streams - Domain Discovery
	StreamDomainDiscoveryQueue   = "domain_discovery_queue"   // Input stream for domain discovery jobs
	StreamDomainDiscoveryResults = "domain_discovery_results" // Output stream for domain discovery findings (consumed by ingestion service)

	// Redis Streams - IP/Port Discovery
	StreamIPDiscoveryQueue   = "ip_discovery_queue"   // Input stream for IP port discovery jobs
	StreamIPDiscoveryResults = "ip_discovery_results" // Output stream for IP port discovery findings (consumed by ingestion service)

	// Redis Streams - Security Findings
	StreamSecurityFindings = "security_findings" // Output stream for security findings from scanning tools (consumed by findings ingestion)

	// Redis Streams - Asset Enrichment
	StreamAssetEnrichmentResults = "asset_enrichment_results" // Output stream for asset enrichment data (consumed by enrichment ingestion)

	// Asset Types (for Discovery.AssetType)
	AssetTypeDomain    = "domain"
	AssetTypeSubdomain = "subdomain"
	AssetTypeIP        = "ip"
	AssetTypePort      = "port"

	// Discovery Asset Status (technical state)
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"

	or                                   // Ownership Status (organizational state)
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
)
