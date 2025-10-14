package shared

import "time"

// This package contains only truly cross-cutting concerns.
// Each vertical slice owns its own models in its respective package.

// DiscoveryJob represents a job to discover attack surface assets
// This is the shared job format consumed by all discovery providers (Shodan, Nmap, Masscan, etc.)
type DiscoveryJob struct {
	TraceID  string                 `json:"trace_id" bson:"trace_id"`
	ParentID *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host     string                 `json:"host" bson:"host"`
	Port     *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created  time.Time              `json:"created" bson:"created"`
}

// AttackSurfaceAsset represents a discovered asset in the attack surface
// This is written to MongoDB by all discovery providers
type AttackSurfaceAsset struct {
	ID        string                 `json:"_id" bson:"_id"`
	ParentID  *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host      string                 `json:"host" bson:"host"`
	Port      *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol  *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Status    string                 `json:"status" bson:"status"` // active, inactive, unknown
	FirstSeen time.Time              `json:"first_seen" bson:"first_seen"`
	LastSeen  time.Time              `json:"last_seen" bson:"last_seen"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}
