package attack_surface

import "time"

// AttackSurfaceJob represents a job to discover attack surface assets
type AttackSurfaceJob struct {
	TraceID  string                 `json:"trace_id" bson:"trace_id"`
	OrgID    string                 `json:"org_id" bson:"org_id"`
	ParentID *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host     string                 `json:"host" bson:"host"`
	Port     *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created  time.Time              `json:"created" bson:"created"`
}

// AttackSurfaceAsset represents a discovered asset in the attack surface
type AttackSurfaceAsset struct {
	ID        string                 `json:"_id" bson:"_id"`
	OrgID     string                 `json:"org_id" bson:"org_id"`
	ParentID  *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host      string                 `json:"host" bson:"host"`
	Port      *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Status    string                 `json:"status" bson:"status"` // active, inactive, unknown
	FirstSeen time.Time              `json:"first_seen" bson:"first_seen"`
	LastSeen  time.Time              `json:"last_seen" bson:"last_seen"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}
