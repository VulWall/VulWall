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
// This is published to vulwall:discoveries by all discovery services
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

// AttackSurfaceAsset represents a discovered asset in the attack surface
// This is written to MongoDB by all discovery providers
type AttackSurfaceAsset struct {
	ID        string                 `json:"_id" bson:"_id"`
	Host      string                 `json:"host" bson:"host"`
	Port      *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol  *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Status    string                 `json:"status" bson:"status"` // active, inactive, unknown
	Source    string                 `json:"source" bson:"source"` // "port_discovery", "nmap", "masscan", etc.
	Banner    *string                `json:"banner,omitempty" bson:"banner,omitempty"` // Service banner (if available)
	FirstSeen time.Time              `json:"first_seen" bson:"first_seen"`
	LastSeen  time.Time              `json:"last_seen" bson:"last_seen"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// ResolutionHistory tracks IP resolution history for a domain
type ResolutionHistory struct {
	IP              string     `json:"ip" bson:"ip"`
	AttackSurfaceID *string    `json:"attacksurface_id,omitempty" bson:"attacksurface_id,omitempty"` // Links to AttackSurfaceAsset
	ResolvedFrom    time.Time  `json:"resolved_from" bson:"resolved_from"`
	ResolvedUntil   *time.Time `json:"resolved_until,omitempty" bson:"resolved_until,omitempty"` // nil means currently active
}

// OrgDomain represents a domain discovered for an organization
// Used to track domain-to-IP resolution history
type OrgDomain struct {
	ID                string              `json:"_id" bson:"_id"`
	OrgID             string              `json:"org_id" bson:"org_id"`
	Domain            string              `json:"domain" bson:"domain"`
	Source            string              `json:"source" bson:"source"` // "shodan", "nmap", etc.
	ResolutionHistory []ResolutionHistory `json:"resolution_history" bson:"resolution_history"`
}

// IPDiscoveryJob represents a job to discover open ports on an IP address
// This is consumed by port discovery services (port_discovery, etc.)
type IPDiscoveryJob struct {
	TraceID   string                 `json:"trace_id" bson:"trace_id"`
	OrgID     string                 `json:"org_id" bson:"org_id"` // Required: organization GUID
	IP        string                 `json:"ip" bson:"ip"`                                     // Target IP address
	PortRange *string                `json:"port_range,omitempty" bson:"port_range,omitempty"` // Optional: "1-1000" or "80,443,22"
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created   time.Time              `json:"created" bson:"created"`
}

// IPDiscoveryFinding represents a discovered open port on an IP
// This is published to ip_discovery_results by port discovery services
type IPDiscoveryFinding struct {
	TraceID   string                 `json:"trace_id" bson:"trace_id"`
	OrgID     string                 `json:"org_id" bson:"org_id"` // Required: organization GUID
	Source    string                 `json:"source" bson:"source"` // "port_discovery", etc.
	IP        string                 `json:"ip" bson:"ip"`
	Port      int                    `json:"port" bson:"port"`
	Protocol  string                 `json:"protocol" bson:"protocol"` // tcp, udp
	Status    string                 `json:"status" bson:"status"`     // active, inactive
	Banner    *string                `json:"banner,omitempty" bson:"banner,omitempty"` // Service banner (if available)
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp time.Time              `json:"timestamp" bson:"timestamp"`
}

// OrgAttackSurface represents the relationship between an organization and an attack surface asset
// This links organizations to attack surface assets they own/monitor
// NOTE: Source of discovery is stored in AttackSurfaceAsset.Source, not here
type OrgAttackSurface struct {
	ID              string    `json:"_id" bson:"_id"`
	AttackSurfaceID string    `json:"attacksurface_id" bson:"attacksurface_id"` // References AttackSurfaceAsset._id
	OrgID           string    `json:"org_id" bson:"org_id"`                     // Organization GUID
	Status          string    `json:"status" bson:"status"`                     // "confirmed", "pending", "dismissed"
	AssignedAt      time.Time `json:"assigned_at" bson:"assigned_at"`           // When the asset was assigned to this org
}
