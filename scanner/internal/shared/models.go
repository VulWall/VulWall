package shared

import "time"

// ScanJob represents a scan task to be processed
type ScanJob struct {
	ScanID  string     `json:"scan_id" bson:"scan_id"`
	Type    string     `json:"type" bson:"type"` // active_recon, passive_recon, vuln_scan, report_gen
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

// ScanResult represents the output of a scan
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

// ActiveReconResult contains active reconnaissance findings
type ActiveReconResult struct {
	OpenPorts    []Port            `json:"open_ports" bson:"open_ports"`
	Services     []Service         `json:"services" bson:"services"`
	Headers      map[string]string `json:"headers" bson:"headers"`
	Screenshots  []string          `json:"screenshots" bson:"screenshots"`
	Certificates []Certificate     `json:"certificates" bson:"certificates"`
}

// Technology represents detected software/framework
type Technology struct {
	Name       string   `json:"name" bson:"name"`
	Version    string   `json:"version,omitempty" bson:"version,omitempty"`
	Categories []string `json:"categories" bson:"categories"`
	Confidence int      `json:"confidence" bson:"confidence"` // 0-100
}

// Port represents an open port
type Port struct {
	Number   int    `json:"number" bson:"number"`
	Protocol string `json:"protocol" bson:"protocol"`
	State    string `json:"state" bson:"state"`
	Service  string `json:"service,omitempty" bson:"service,omitempty"`
}

// Service represents a detected service
type Service struct {
	Name    string `json:"name" bson:"name"`
	Version string `json:"version,omitempty" bson:"version,omitempty"`
	Port    int    `json:"port" bson:"port"`
	Banner  string `json:"banner,omitempty" bson:"banner,omitempty"`
}

// Certificate represents an SSL/TLS certificate
type Certificate struct {
	Subject  string    `json:"subject" bson:"subject"`
	Issuer   string    `json:"issuer" bson:"issuer"`
	NotAfter time.Time `json:"not_after" bson:"not_after"`
	SANs     []string  `json:"sans" bson:"sans"`
}
