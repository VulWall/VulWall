package passive_recon

import "time"

// ScanJob represents a passive reconnaissance scan task
type ScanJob struct {
	ScanID  string     `json:"scan_id" bson:"scan_id"`
	Type    string     `json:"type" bson:"type"`
	Domain  string     `json:"domain" bson:"domain"`
	UserID  string     `json:"user_id" bson:"user_id"`
	Options JobOptions `json:"options" bson:"options"`
	Created time.Time  `json:"created" bson:"created"`
}

// JobOptions contains scan-specific configuration
type JobOptions struct {
	Aggressive bool     `json:"aggressive" bson:"aggressive"`
	Ports      []int    `json:"ports,omitempty" bson:"ports,omitempty"`
	Threads    int      `json:"threads" bson:"threads"`
	Timeout    int      `json:"timeout" bson:"timeout"` // in seconds
	Tags       []string `json:"tags,omitempty" bson:"tags,omitempty"`
}

// ScanResult represents the output of a passive recon scan
type ScanResult struct {
	ScanID      string      `json:"scan_id" bson:"scan_id"`
	Type        string      `json:"type" bson:"type"`
	Status      string      `json:"status" bson:"status"` // pending, running, completed, failed
	Results     interface{} `json:"results" bson:"results"`
	Error       string      `json:"error,omitempty" bson:"error,omitempty"`
	StartedAt   time.Time   `json:"started_at" bson:"started_at"`
	CompletedAt *time.Time  `json:"completed_at,omitempty" bson:"completed_at,omitempty"`
	Duration    float64     `json:"duration" bson:"duration"` // in seconds
}

// PassiveReconResult contains passive reconnaissance findings
type PassiveReconResult struct {
	Subdomains   []string          `json:"subdomains" bson:"subdomains"`
	DNSRecords   map[string]string `json:"dns_records" bson:"dns_records"`
	Technologies []Technology      `json:"technologies" bson:"technologies"`
	Metadata     map[string]string `json:"metadata" bson:"metadata"`
}

// Technology represents detected software/framework
type Technology struct {
	Name       string   `json:"name" bson:"name"`
	Version    string   `json:"version,omitempty" bson:"version,omitempty"`
	Categories []string `json:"categories" bson:"categories"`
	Confidence int      `json:"confidence" bson:"confidence"` // 0-100
}
