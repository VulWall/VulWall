package active_recon

import "time"

// ScanJob represents an active reconnaissance scan task
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

// ScanResult represents the output of an active recon scan
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

// ActiveReconResult contains active reconnaissance findings
type ActiveReconResult struct {
	OpenPorts    []Port            `json:"open_ports" bson:"open_ports"`
	Services     []ServiceInfo     `json:"services" bson:"services"`
	Headers      map[string]string `json:"headers" bson:"headers"`
	Screenshots  []string          `json:"screenshots" bson:"screenshots"`
	Certificates []Certificate     `json:"certificates" bson:"certificates"`
}

// Port represents an open port
type Port struct {
	Number   int    `json:"number" bson:"number"`
	Protocol string `json:"protocol" bson:"protocol"`
	State    string `json:"state" bson:"state"`
	Service  string `json:"service,omitempty" bson:"service,omitempty"`
}

// ServiceInfo represents a detected service
type ServiceInfo struct {
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
