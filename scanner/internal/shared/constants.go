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

	// Redis Streams
	StreamDiscovery  = "vulwall:discovery"  // Input stream for discovery jobs
	StreamDiscoveries = "vulwall:discoveries" // Output stream for discovery findings (consumed by ingestion service)

	// Attack Surface Asset Status
	AssetStatusActive   = "active"
	AssetStatusInactive = "inactive"
	AssetStatusUnknown  = "unknown"

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
