package shared

import "time"

// This package contains only truly cross-cutting concerns.
// Each vertical slice owns its own models in its respective package.

// DiscoveryJob represents a job to discover attack surface assets
// This is the shared job format consumed by all discovery providers (Shodan, Nmap, Masscan, etc.)
type DiscoveryJob struct {
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"` // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"` // Optional: scan identifier for linking to UI scans
	OrgID        string                 `json:"org_id" bson:"org_id"`                       // Required: organization GUID
	ParentID     *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host         string                 `json:"host" bson:"host"`
	Port         *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol     *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created      time.Time              `json:"created" bson:"created"`
}

// DiscoveryFinding represents a discovery result from any discovery service
// This is published to domain_discovery_results by all domain discovery services
type DiscoveryFinding struct {
	DiscoveryID  string                 `json:"discovery_id" bson:"discovery_id"` // Deterministic UUID for this discovery
	AssetType    string                 `json:"asset_type" bson:"asset_type"`     // "domain", "subdomain", "ip"
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"` // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"` // Optional: scan identifier for linking to UI scans
	OrgID        string                 `json:"org_id" bson:"org_id"`                       // Required: organization GUID
	Scanner      string                 `json:"scanner" bson:"scanner"`                     // Scanner name: "shodan", "nmap", "masscan", etc.
	ParentID     *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host         string                 `json:"host" bson:"host"`
	IP           *string                `json:"ip,omitempty" bson:"ip,omitempty"` // IP address (if resolved)
	Port         *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol     *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Status       string                 `json:"status" bson:"status"` // active, inactive, unknown
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp"`
}

// IPDiscoveryJob represents a job to discover open ports on an IP address
// This is consumed by port discovery services (port_discovery, etc.)
type IPDiscoveryJob struct {
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`                 // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"`       // Optional: scan identifier for linking to UI scans
	OrgID        string                 `json:"org_id" bson:"org_id"`                             // Required: organization GUID
	ParentID     *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`   // Parent IP discovery ID
	IP           string                 `json:"ip" bson:"ip"`                                     // Target IP address
	PortRange    *string                `json:"port_range,omitempty" bson:"port_range,omitempty"` // Optional: "1-1000" or "80,443,22"
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Created      time.Time              `json:"created" bson:"created"`
}

// IPDiscoveryFinding represents a discovered open port on an IP
// This is published to ip_discovery_results by port discovery services
type IPDiscoveryFinding struct {
	DiscoveryID  string                 `json:"discovery_id" bson:"discovery_id"` // Deterministic UUID for this port discovery
	AssetType    string                 `json:"asset_type" bson:"asset_type"`     // "ip", "port"
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`               // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"`     // Optional: scan identifier for linking to UI scans
	OrgID        string                 `json:"org_id" bson:"org_id"`                           // Required: organization GUID
	Scanner      string                 `json:"scanner" bson:"scanner"`                         // Scanner name: "port_discovery", etc.
	ParentID     *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"` // Parent IP discovery ID
	IP           string                 `json:"ip" bson:"ip"`
	Port         int                    `json:"port" bson:"port"`
	Protocol     string                 `json:"protocol" bson:"protocol"` // tcp, udp
	Status       string                 `json:"status" bson:"status"`     // active, inactive
	Banner       *string                `json:"banner,omitempty" bson:"banner,omitempty"`
	ServiceName  *string                `json:"service_name,omitempty" bson:"service_name,omitempty"`
	Product      *string                `json:"product,omitempty" bson:"product,omitempty"`
	Version      *string                `json:"version,omitempty" bson:"version,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp"`
}

// Discovery represents a discovered asset scoped to an organization
// Uses type discrimination to store different asset types (domain, subdomain, ip, port)
// Each organization has separate discovery records (no deduplication across orgs)
type Discovery struct {
	ID              string                 `json:"_id" bson:"_id"`
	OrgID           string                 `json:"org_id" bson:"org_id"`                           // Organization GUID
	ScanIDs         []string               `json:"scan_ids,omitempty" bson:"scan_ids,omitempty"`   // Array of scan identifiers that detected this asset
	AssetType       string                 `json:"asset_type" bson:"asset_type"`                   // "domain", "subdomain", "ip", "port"
	Scanner         string                 `json:"scanner" bson:"scanner"`                         // Scanner name that discovered this asset
	Status          string                 `json:"status" bson:"status"`                           // active, inactive, unknown (technical state)
	OwnershipStatus string                 `json:"ownership_status" bson:"ownership_status"`       // "verified", "NotMine", "NotSure" (organizational state)
	DiscoveredAt    time.Time              `json:"discovered_at" bson:"discovered_at"`             // When asset was discovered
	ParentID        *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"` // Parent asset ID—for ports, this is the IP discovery ID; for IPs discovered from domains, this is the domain discovery ID; for subdomains, this is the parent domain discovery ID (all org-scoped)
	FirstSeen       time.Time              `json:"first_seen" bson:"first_seen"`
	LastSeen        time.Time              `json:"last_seen" bson:"last_seen"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`

	// Domain-specific fields (when asset_type = "domain")
	Domain            *string                  `json:"domain,omitempty" bson:"domain,omitempty"`
	ResolutionHistory []ResolutionHistoryEntry `json:"resolution_history,omitempty" bson:"resolution_history,omitempty"`

	// Subdomain-specific fields (when asset_type = "subdomain")
	Subdomain *string `json:"subdomain,omitempty" bson:"subdomain,omitempty"`
	// Note: Subdomains also use resolution_history

	// IP-specific fields (when asset_type = "ip")
	IP *string `json:"ip,omitempty" bson:"ip,omitempty"`

	// Port-specific fields (when asset_type = "port")
	// IP field reused for port assets
	Port             *int                  `json:"port,omitempty" bson:"port,omitempty"`
	Protocol         *string               `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Banner           *string               `json:"banner,omitempty" bson:"banner,omitempty"`
	ServiceName      *string               `json:"service_name,omitempty" bson:"service_name,omitempty"`
	Product          *string               `json:"product,omitempty" bson:"product,omitempty"`
	Version          *string               `json:"version,omitempty" bson:"version,omitempty"`
	PreviousServices []ServiceHistoryEntry `json:"previous_services,omitempty" bson:"previous_services,omitempty"`
}

// ResolutionHistoryEntry tracks IP resolution changes for domains and subdomains
type ResolutionHistoryEntry struct {
	IP        string     `json:"ip" bson:"ip"`
	FirstSeen time.Time  `json:"first_seen" bson:"first_seen"`
	LastSeen  *time.Time `json:"last_seen,omitempty" bson:"last_seen,omitempty"` // nil = currently active
}

// ServiceHistoryEntry tracks service changes on a port over time
type ServiceHistoryEntry struct {
	ServiceName string    `json:"service_name" bson:"service_name"`
	Product     *string   `json:"product,omitempty" bson:"product,omitempty"`
	Version     *string   `json:"version,omitempty" bson:"version,omitempty"`
	Banner      *string   `json:"banner,omitempty" bson:"banner,omitempty"`
	LastSeen    time.Time `json:"last_seen" bson:"last_seen"`
}

// SecurityFinding represents a security vulnerability or finding from scanning tools
// Published to security_findings stream and persisted to findings collection
type SecurityFinding struct {
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`             // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"`   // Optional: scan identifier from current scan (for stream messages)
	OrgID        string                 `json:"org_id" bson:"org_id"`                         // Organization GUID
	Scanner      string                 `json:"scanner" bson:"scanner"`                       // Scanner name (e.g., "nuclei", "jsscanner")
	DiscoveryID  string                 `json:"discovery_id" bson:"discovery_id"`             // Links to Discovery._id
	FindingType  string                 `json:"finding_type" bson:"finding_type"`             // Type of finding (e.g., "xss", "sqli", "cve-2021-1234")
	Severity     string                 `json:"severity" bson:"severity"`                     // info, low, medium, high, critical
	Title        string                 `json:"title" bson:"title"`                           // Short title
	Description  string                 `json:"description" bson:"description"`               // Detailed description
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"` // Scanner-specific data
	Status       string                 `json:"status" bson:"status"`                         // open, resolved
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp"`                   // When finding was discovered
}

// ScanTarget represents a target to be scanned by active recon scanners
// Used by nuclei_scanner, testssl_scanner, webtechprofiler
type ScanTarget struct {
	Target      string  `json:"target"`        // URL, IP, or Host:port to scan
	AssetType   string  `json:"asset_type"`    // Asset type: domain, subdomain, ip, port
	DiscoveryID string  `json:"discovery_id"`  // Links back to Discovery._id
	TraceID     string  `json:"trace_id"`      // Request tracing ID
	ScanID      *string `json:"scan_id,omitempty"` // Optional: scan identifier for linking to UI scans
	OrgID       string  `json:"org_id"`        // Organization GUID
}

// EnrichmentJob represents a request to enrich a discovered asset
// Published by ingestion services to discovery_enrichment_queue
type EnrichmentJob struct {
	TraceID      string            `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string `json:"trace_context,omitempty" bson:"-"`       // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string           `json:"scan_id,omitempty" bson:"scan_id,omitempty"` // Optional: scan identifier
	OrgID        string            `json:"org_id" bson:"org_id"`                       // Organization GUID
	DiscoveryID  string            `json:"discovery_id" bson:"discovery_id"`           // Discovery ID to enrich
	AssetType    string            `json:"asset_type" bson:"asset_type"`               // "domain", "subdomain", "ip" (NOT "port")
	Host         string            `json:"host,omitempty" bson:"host,omitempty"`       // Domain/subdomain name (for WAF detection)
	IP           string            `json:"ip,omitempty" bson:"ip,omitempty"`           // IP address (for geolocation)
	Created      time.Time         `json:"created" bson:"created"`
}

// EnrichmentFinding represents enrichment data for discovered assets
// Published to asset_enrichment_results stream and merged into discoveries collection metadata
type EnrichmentFinding struct {
	TraceID        string                 `json:"trace_id" bson:"trace_id"`
	TraceContext   map[string]string      `json:"trace_context,omitempty" bson:"-"`       // W3C TraceContext headers for span linking (not stored in DB)
	ScanID         *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"` // Optional: scan identifier
	OrgID          string                 `json:"org_id" bson:"org_id"`                       // Organization GUID
	Scanner        string                 `json:"scanner" bson:"scanner"`                     // Scanner name (e.g., "discovery_enrichment")
	DiscoveryID    string                 `json:"discovery_id" bson:"discovery_id"`           // Links to Discovery._id
	EnrichmentType string                 `json:"enrichment_type" bson:"enrichment_type"`     // Type of enrichment (e.g., "waf", "cdn", "tech_stack")
	Data           map[string]interface{} `json:"data" bson:"data"`                           // Enrichment data (e.g., {"waf_name": "Cloudflare"})
	Timestamp      time.Time              `json:"timestamp" bson:"timestamp"`                 // When enrichment was performed
}

// Asset represents a user-added asset to be scanned
// Stored in assets collection (user-managed assets, not scan discoveries)
// Matches VulWall.Dashboard.Data.Entities.Asset.Asset entity
type Asset struct {
	ID            string     `json:"_id,omitempty" bson:"_id,omitempty"`
	OrgID         string     `json:"org_id" bson:"org_id"`
	Type          string     `json:"type" bson:"type"`                                           // "domain", "ip"
	Enabled       bool       `json:"enabled" bson:"enabled"`                                     // true = enabled, false = disabled
	DNSVerifiedAt *time.Time `json:"dns_verified_at,omitempty" bson:"dns_verified_at,omitempty"` // DNS verification timestamp
	Domain        *string    `json:"domain,omitempty" bson:"domain,omitempty"`                   // For domain assets
	IP            *string    `json:"ip,omitempty" bson:"ip,omitempty"`                           // For IP assets
	AddedOn       time.Time  `json:"added_on" bson:"added_on"`                                   // When asset was added
}

// Organization represents an organization with subscription settings
// Stored in organizations collection
type Organization struct {
	ID                   string               `json:"_id" bson:"_id"`
	UserIDs              []string             `json:"user_ids" bson:"user_ids"`
	CompanyName          string               `json:"company_name" bson:"company_name"`
	Industry             string               `json:"industry" bson:"industry"`
	Website              string               `json:"website" bson:"website"`
	CertVisible          bool                 `json:"cert_visible" bson:"cert_visible"`
	CreatedAt            time.Time            `json:"created_at" bson:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at" bson:"updated_at"`
	SubscriptionSettings SubscriptionSettings `json:"subscription_settings" bson:"subscription_settings"`
}

// SubscriptionSettings contains subscription-specific settings for scanning
type SubscriptionSettings struct {
	ScanIntervalDays int `json:"scan_interval_days" bson:"scan_interval_days"` // How often to scan assets
	MaxAssets        int `json:"max_assets" bson:"max_assets"`                 // Maximum number of assets allowed
}

// Scan represents a scan execution in the system
// Stored in scans collection
type Scan struct {
	ID          string     `json:"_id" bson:"_id"`                                       // Scan UUID
	OrgID       string     `json:"org_id" bson:"org_id"`                                 // Organization GUID
	Status      string     `json:"status" bson:"status"`                                 // "pending", "running", "completed", "failed"
	Type        string     `json:"type" bson:"type"`                                     // "manual", "scheduled", "on_demand"
	TriggeredBy string     `json:"triggered_by,omitempty" bson:"triggered_by,omitempty"` // User ID or "system"
	StartedAt   *time.Time `json:"started_at,omitempty" bson:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty" bson:"completed_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" bson:"updated_at"`

	// Assets that were targeted for scanning (input)
	TargetedAssets []AssetTarget `json:"targeted_assets,omitempty" bson:"targeted_assets,omitempty"`

	// Scan statistics (populated as scan progresses)
	Stats ScanStats `json:"stats,omitempty" bson:"stats,omitempty"`
}

// ScanStats tracks statistics for a scan execution
type ScanStats struct {
	TotalAssets      int `json:"total_assets" bson:"total_assets"`
	AssetsScanned    int `json:"assets_scanned" bson:"assets_scanned"`
	NewAssets        int `json:"new_assets" bson:"new_assets"`
	FindingsDetected int `json:"findings_detected" bson:"findings_detected"`
}

// AssetTarget represents an asset that was targeted for scanning
// Stored in Scan.TargetedAssets array for audit trail
type AssetTarget struct {
	AssetID string `json:"asset_id" bson:"asset_id"` // References assets._id
	Type    string `json:"type" bson:"type"`         // "domain" or "ip"
	Value   string `json:"value" bson:"value"`       // Domain name or IP address
}

// SystemAuditEvent represents a system-level audit log event
// Used by services to publish events to be persisted by ingestion
// Persisted to the existing audit_logs collection
type SystemAuditEvent struct {
	TraceID        string                 `json:"trace_id,omitempty" bson:"trace_id,omitempty"`
	TraceContext   map[string]string      `json:"trace_context,omitempty" bson:"-"` // W3C TraceContext (not stored in DB)
	Category       string                 `json:"category" bson:"Category"`         // "TemplateUpdate", "ServiceStart", etc.
	Action         string                 `json:"action" bson:"Action"`             // Human-readable action description
	Service        string                 `json:"service" bson:"service"`           // "nuclei-scanner", "scan-coordinator", etc.
	Success        bool                   `json:"success" bson:"success"`
	AdditionalInfo map[string]interface{} `json:"additional_info,omitempty" bson:"AdditionalInfo"`
	Timestamp      time.Time              `json:"timestamp" bson:"CreatedAt"`
}

// AIEnrichmentFinding represents AI-generated recommendations for security findings
// Published to ai_enrichment_results stream and merged into findings collection
// Uses composite key (org_id + discovery_id + finding_type + title) to match findings
type AIEnrichmentFinding struct {
	TraceID        string                 `json:"trace_id" bson:"trace_id"`
	TraceContext   map[string]string      `json:"trace_context,omitempty" bson:"-"`     // W3C TraceContext headers for span linking (not stored in DB)
	OrgID          string                 `json:"org_id" bson:"org_id"`                 // Organization GUID
	DiscoveryID    string                 `json:"discovery_id" bson:"discovery_id"`     // Part of composite key
	FindingType    string                 `json:"finding_type" bson:"finding_type"`     // Part of composite key
	Title          string                 `json:"title" bson:"title"`                   // Part of composite key
	Recommendation map[string]interface{} `json:"recommendation" bson:"recommendation"` // AI-generated structured recommendation (stored as BSON object)
	PromptUsed     string                 `json:"prompt_used" bson:"prompt_used"`       // Prompt identifier (e.g., "recommendation")
	Model          string                 `json:"model" bson:"model"`                   // Model used (e.g., "llama-3.3-70b-versatile")
	Timestamp      time.Time              `json:"timestamp" bson:"timestamp"`           // When recommendation was generated
}
