package shared

const (
	// Scan Status
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"

	// MongoDB Collections
	CollectionScanResults = "scan_results"
	CollectionDiscoveries = "discoveries" // Global asset registry (domains, subdomains, IPs, ports)
	CollectionOrgAssets   = "org_assets"  // Org-to-asset relationship links

	// Redis Streams - Domain Discovery
	StreamDomainDiscoveryQueue   = "domain_discovery_queue"   // Input stream for domain discovery jobs
	StreamDomainDiscoveryResults = "domain_discovery_results" // Output stream for domain discovery findings (consumed by ingestion service)

	// Redis Streams - IP/Port Discovery
	StreamIPDiscoveryQueue   = "ip_discovery_queue"   // Input stream for IP port discovery jobs
	StreamIPDiscoveryResults = "ip_discovery_results" // Output stream for IP port discovery findings (consumed by ingestion service)

	// Asset Types (for Discovery.AssetType)
	AssetTypeDomain    = "domain"
	AssetTypeSubdomain = "subdomain"
	AssetTypeIP        = "ip"
	AssetTypePort      = "port"

	// Discovery Asset Status (technical state)
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"

	// Org Asset Link Status (organizational state)
	OrgAssetStatusConfirmed = "confirmed" // Asset confirmed to belong to org
	OrgAssetStatusPending   = "pending"   // Asset pending verification
	OrgAssetStatusDismissed = "dismissed" // Asset dismissed/not relevant to org

	// Protocol constants
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolSCTP = "sctp"
	ProtocolICMP = "icmp"

	// Discovery target type constants
	TargetTypeDomain = "domain"
	TargetTypeIP     = "ip"
	TargetTypeCIDR   = "cidr"
)
