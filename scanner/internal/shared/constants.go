package shared

const (
	// Scan Status
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"

	// MongoDB Collections
	CollectionScanResults      = "scan_results"
	CollectionAttackSurface    = "attack_surface"
	CollectionOrgAttackSurface = "org_attack_surface"
	CollectionOrgAssets        = "org_assets" // Unified collection for domains and IPs
	CollectionOrgDomains       = "org_domains" // DEPRECATED: Use CollectionOrgAssets instead

	// Redis Streams - Domain Discovery
	StreamDomainDiscoveryQueue   = "domain_discovery_queue"   // Input stream for domain discovery jobs
	StreamDomainDiscoveryResults = "domain_discovery_results" // Output stream for domain discovery findings (consumed by ingestion service)

	// Redis Streams - IP/Port Discovery
	StreamIPDiscoveryQueue   = "ip_discovery_queue"   // Input stream for IP port discovery jobs
	StreamIPDiscoveryResults = "ip_discovery_results" // Output stream for IP port discovery findings (consumed by ingestion service)

	// Attack Surface Asset Status
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"

	// Org Attack Surface Status
	OrgAssetStatusConfirmed = "confirmed"
	OrgAssetStatusPending   = "pending"
	OrgAssetStatusDismissed = "dismissed"

	// Protocol constants
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolSCTP = "sctp"
	ProtocolICMP = "icmp"

	// Discovery target type constants
	TargetTypeDomain = "domain"
	TargetTypeIP     = "ip"
	TargetTypeCIDR   = "cidr"

	// Asset type constants (for OrgAsset.AssetType)
	AssetTypeDomain = "domain"
	AssetTypeIP     = "ip"
)
