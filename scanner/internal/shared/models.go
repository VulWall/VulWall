package shared

import "time"

// This package contains only truly cross-cutting concerns.
// Each vertical slice owns its own models in its respective package.

// DiscoveryJob represents a job to discover attack surface assets
// This is the shared job format consumed by all discovery providers (Shodan, Nmap, Masscan, etc.)
type DiscoveryJob struct {
	TraceID  string                 `json:"trace_id" bson:"trace_id"`
	OrgID    string                 `json:"org_id" bson:"org_id"` // Required: organization GUID
	ParentID *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host     string                 `json:"host" bson:"host"`
	Port     *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created  time.Time              `json:"created" bson:"created"`
}

// DiscoveryFinding represents a discovery result from any discovery service
// This is published to domain_discovery_results by all domain discovery services
type DiscoveryFinding struct {
	TraceID   string                 `json:"trace_id" bson:"trace_id"`
	OrgID     string                 `json:"org_id" bson:"org_id"` // Required: organization GUID
	Source    string                 `json:"source" bson:"source"` // "shodan", "nmap", "masscan", etc.
	ParentID  *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host      string                 `json:"host" bson:"host"`
	IP        *string                `json:"ip,omitempty" bson:"ip,omitempty"` // IP address (if resolved)
	Port      *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol  *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Status    string                 `json:"status" bson:"status"` // active, inactive, unknown
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp time.Time              `json:"timestamp" bson:"timestamp"`
}

// IPDiscoveryJob represents a job to discover open ports on an IP address
// This is consumed by port discovery services (port_discovery, etc.)
type IPDiscoveryJob struct {
	TraceID   string                 `json:"trace_id" bson:"trace_id"`
	OrgID     string                 `json:"org_id" bson:"org_id"` // Required: organization GUID
	ParentID  *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"` // Parent IP discovery ID
	IP        string                 `json:"ip" bson:"ip"`                                     // Target IP address
	PortRange *string                `json:"port_range,omitempty" bson:"port_range,omitempty"` // Optional: "1-1000" or "80,443,22"
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created   time.Time              `json:"created" bson:"created"`
}

// IPDiscoveryFinding represents a discovered open port on an IP
// This is published to ip_discovery_results by port discovery services
type IPDiscoveryFinding struct {
	TraceID     string                 `json:"trace_id" bson:"trace_id"`
	OrgID       string                 `json:"org_id" bson:"org_id"` // Required: organization GUID
	Source      string                 `json:"source" bson:"source"` // "port_discovery", etc.
	ParentID    *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"` // Parent IP discovery ID
	IP          string                 `json:"ip" bson:"ip"`
	Port        int                    `json:"port" bson:"port"`
	Protocol    string                 `json:"protocol" bson:"protocol"` // tcp, udp
	Status      string                 `json:"status" bson:"status"`     // active, inactive
	Banner      *string                `json:"banner,omitempty" bson:"banner,omitempty"`
	ServiceName *string                `json:"service_name,omitempty" bson:"service_name,omitempty"`
	Product     *string                `json:"product,omitempty" bson:"product,omitempty"`
	Version     *string                `json:"version,omitempty" bson:"version,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp   time.Time              `json:"timestamp" bson:"timestamp"`
}

// Discovery represents a discovered asset in the global discoveries collection
// Uses type discrimination to store different asset types (domain, subdomain, ip, port)
type Discovery struct {
	ID         string    `json:"_id" bson:"_id"`
	AssetType  string    `json:"asset_type" bson:"asset_type"` // "domain", "subdomain", "ip", "port"
	Source     string    `json:"source" bson:"source"`         // Discovery source
	Status     string    `json:"status" bson:"status"`         // active, inactive, unknown
	ParentID   *string   `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	FirstSeen  time.Time `json:"first_seen" bson:"first_seen"`
	LastSeen   time.Time `json:"last_seen" bson:"last_seen"`
	Metadata   map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`

	// Domain-specific fields (when asset_type = "domain")
	Domain            *string                   `json:"domain,omitempty" bson:"domain,omitempty"`
	ResolutionHistory []ResolutionHistoryEntry  `json:"resolution_history,omitempty" bson:"resolution_history,omitempty"`

	// Subdomain-specific fields (when asset_type = "subdomain")
	Subdomain *string `json:"subdomain,omitempty" bson:"subdomain,omitempty"`
	// Note: Subdomains also use resolution_history

	// IP-specific fields (when asset_type = "ip")
	IP *string `json:"ip,omitempty" bson:"ip,omitempty"`

	// Port-specific fields (when asset_type = "port")
	// IP field reused for port assets
	Port             *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol         *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Banner           *string                `json:"banner,omitempty" bson:"banner,omitempty"`
	ServiceName      *string                `json:"service_name,omitempty" bson:"service_name,omitempty"`
	Product          *string                `json:"product,omitempty" bson:"product,omitempty"`
	Version          *string                `json:"version,omitempty" bson:"version,omitempty"`
	PreviousServices []ServiceHistoryEntry  `json:"previous_services,omitempty" bson:"previous_services,omitempty"`
}

// ResolutionHistoryEntry tracks IP resolution changes for domains and subdomains
type ResolutionHistoryEntry struct {
	IP        string     `json:"ip" bson:"ip"`
	FirstSeen time.Time  `json:"first_seen" bson:"first_seen"`
	LastSeen  *time.Time `json:"last_seen,omitempty" bson:"last_seen,omitempty"` // nil = currently active
}

// ServiceHistoryEntry tracks service changes on a port over time
type ServiceHistoryEntry struct {
	ServiceName string     `json:"service_name" bson:"service_name"`
	Product     *string    `json:"product,omitempty" bson:"product,omitempty"`
	Version     *string    `json:"version,omitempty" bson:"version,omitempty"`
	Banner      *string    `json:"banner,omitempty" bson:"banner,omitempty"`
	LastSeen    time.Time  `json:"last_seen" bson:"last_seen"`
}

// OrgAssetLink represents the relationship between an organization and a discovered asset
// This creates a many-to-many relationship (same asset can belong to multiple orgs)
type OrgAssetLink struct {
	ID         string    `json:"_id" bson:"_id"`
	OrgID      string    `json:"org_id" bson:"org_id"`         // Organization GUID
	AssetID    string    `json:"asset_id" bson:"asset_id"`     // References Discovery._id
	Status     string    `json:"status" bson:"status"`         // "confirmed", "pending", "dismissed"
	AssignedAt time.Time `json:"assigned_at" bson:"assigned_at"` // When the asset was assigned to this org
}
