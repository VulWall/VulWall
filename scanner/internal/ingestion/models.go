package ingestion

import "time"

// DiscoveryFinding represents a discovery result from any discovery service
// This is published to vulwall:discoveries by all discovery services
type DiscoveryFinding struct {
	TraceID   string                 `json:"trace_id" bson:"trace_id"`
	Source    string                 `json:"source" bson:"source"`       // "shodan", "nmap", "masscan", etc.
	ParentID  *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host      string                 `json:"host" bson:"host"`
	Port      *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol  *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Status    string                 `json:"status" bson:"status"` // active, inactive, unknown
	Metadata  map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp time.Time              `json:"timestamp" bson:"timestamp"`
}
