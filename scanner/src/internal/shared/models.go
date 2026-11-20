package shared

import "time"

// This package contains only truly cross-cutting concerns.
// Each vertical slice owns its own models in its respective package.

// DiscoveryJob represents a job to discover attack surface assets
// This is the shared job format consumed by all discovery providers (subfinder, Nmap, Masscan, etc.)
type DiscoveryJob struct {
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"` // W3C TraceContext headers for span linking (not stored in DB)
	ScanID       *string                `json:"scan_id,omitempty" bson:"scan_id,omitempty"` // Optional: scan identifier for linking to UI scans
	OrgID        string                 `json:"org_id" bson:"org_id"`                       // Required: organization GUID
	// AssetID is the assets._id the job was made for (empty on jobs from older versions).
	AssetID      string                 `json:"asset_id,omitempty" bson:"asset_id,omitempty"`
	// KnownSubdomains are names below Host that earlier scans saw (filled by the coordinator,
	// which reads discoveries). Domain discovery resolves them even when subfinder does not
	// return them, and confirms with public resolvers that a missing one is really gone.
	KnownSubdomains []string `json:"known_subdomains,omitempty" bson:"-"`
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
	Source       string                 `json:"source" bson:"source"`                       // Source name: "subfinder", "nmap", "masscan", etc.
	ParentID     *string                `json:"parent_id,omitempty" bson:"parent_id,omitempty"`
	Host         string                 `json:"host" bson:"host"`
	IP           *string                `json:"ip,omitempty" bson:"ip,omitempty"` // IP address (if resolved)
	Port         *int                   `json:"port,omitempty" bson:"port,omitempty"`
	Protocol     *string                `json:"protocol,omitempty" bson:"protocol,omitempty"`
	Status       string                 `json:"status" bson:"status"` // active, inactive, unknown
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp"`

	// Degraded marks a message that carries no asset: discovery could not see the whole
	// attack surface of one root domain, so ingestion adds it to the scan's degraded_assets
	// (information for the user). It is published before the discovery job is ACKed, so the
	// scan cannot read as drained before it lands.
	Degraded *DegradedAsset `json:"degraded,omitempty" bson:"-"`
}

// DegradedAsset is one entry of scans.degraded_assets: a root domain asset whose attack
// surface this scan could not fully see. It is information for the user; finding resolution
// does not depend on it (a scan resolves only on positive evidence, see ScanCoverage).
// It holds no timestamp, so $addToSet keeps a redelivered signal from adding a duplicate.
type DegradedAsset struct {
	AssetID string `json:"asset_id,omitempty" bson:"asset_id,omitempty"` // assets._id; empty for jobs from older versions
	Domain  string `json:"domain" bson:"domain"`                         // the root domain as scanned
	Reason  string `json:"reason" bson:"reason"`                         // ScanDegraded*
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
	TargetDomain string                 `json:"target_domain,omitempty" bson:"target_domain,omitempty"` // Domain that resolved to this IP (for CDN ownership checks)
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
	Source       string                 `json:"source" bson:"source"`                           // Source name: "port_discovery", "nmap", etc.
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
	Source          string                 `json:"source" bson:"source"`                           // Source name that discovered this asset
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
	Source       string                 `json:"source" bson:"source"`                         // Source name (e.g., "nuclei", "jsscanner")
	DiscoveryID  string                 `json:"discovery_id" bson:"discovery_id"`             // Links to Discovery._id
	FindingType  string                 `json:"finding_type" bson:"finding_type"`             // Type of finding (e.g., "xss", "sqli", "cve-2021-1234")
	Severity     string                 `json:"severity" bson:"severity"`                     // info, low, medium, high, critical
	Title        string                 `json:"title" bson:"title"`                           // Short title
	Description  string                 `json:"description" bson:"description"`               // Detailed description
	Remediation  string                 `json:"remediation,omitempty" bson:"remediation,omitempty"` // How to fix, when the scanner provides it
	References   []string               `json:"references,omitempty" bson:"references,omitempty"`   // Advisory / documentation URLs
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"` // Scanner-specific data
	Status           string                 `json:"status" bson:"status"`                                                   // open, resolved
	Timestamp        time.Time              `json:"timestamp" bson:"timestamp"`                                             // When finding was discovered
	ResolvedAt       *time.Time             `json:"resolved_at,omitempty" bson:"resolved_at,omitempty"`                     // When finding was resolved (nil if open)
	ResolvedByScanID string                 `json:"resolved_by_scan_id,omitempty" bson:"resolved_by_scan_id,omitempty"`     // Scan that resolved this finding

	// Coverage marks a message that carries no finding but evidence about a target
	// (ScanCoverage). Ingestion stores it in scan_coverage.
	Coverage *ScanCoverage `json:"coverage,omitempty" bson:"-"`
}

// ScanTarget represents a target to be scanned by active recon scanners
// Used by nuclei_scanner, testssl_scanner
type ScanTarget struct {
	Target      string  `json:"target"`        // URL, IP, or Host:port to scan
	AssetType   string  `json:"asset_type"`    // Asset type: domain, subdomain, ip, port
	DiscoveryID string  `json:"discovery_id"`  // Links back to Discovery._id
	TraceID     string  `json:"trace_id"`      // Request tracing ID
	ScanID      *string `json:"scan_id,omitempty"` // Optional: scan identifier for linking to UI scans
	OrgID       string  `json:"org_id"`        // Organization GUID
	// Unresolved is set when the host had no address in this scan. A network check of such a
	// target proves nothing, so its coverage is CoverageError.
	Unresolved bool `json:"-"`
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
	Source         string                 `json:"source" bson:"source"`                       // Source name (e.g., "discovery_enrichment")
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

// Organization represents an organization and its scan schedule
// Stored in organizations collection
type Organization struct {
	ID           string       `json:"_id" bson:"_id"`
	UserIDs      []string     `json:"user_ids" bson:"user_ids"`
	CompanyName  string       `json:"company_name" bson:"company_name"`
	Industry     string       `json:"industry" bson:"industry"`
	Website      string       `json:"website" bson:"website"`
	CreatedAt    time.Time    `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at" bson:"updated_at"`
	ScanSettings ScanSettings `json:"scan_settings" bson:"scan_settings"`
}

// ScanSettings is the organization's scan schedule, written by the web app
type ScanSettings struct {
	ScanCron string `json:"scan_cron" bson:"scan_cron"` // 5-field cron in UTC (e.g., "0 2 * * *" = daily at 02:00 UTC)
	// Enabled is false when the schedule is turned off. A missing field counts as on.
	Enabled *bool `json:"enabled,omitempty" bson:"enabled,omitempty"`
}

// Scheduled reports whether the organization should get scheduled scans.
func (s ScanSettings) Scheduled() bool {
	return (s.Enabled == nil || *s.Enabled) && s.ScanCron != ""
}

// Scan represents a scan execution in the system
// Stored in scans collection
type Scan struct {
	ID          string     `json:"_id" bson:"_id"`                                       // Scan UUID
	OrgID       string     `json:"org_id" bson:"org_id"`                                 // Organization GUID
	Status      string     `json:"status" bson:"status"`                                 // "queued", "pending", "running", "done", "failed"
	Type        string     `json:"type" bson:"type"`                                     // "scheduled", "requested"
	TriggeredBy string     `json:"triggered_by,omitempty" bson:"triggered_by,omitempty"` // User ID or "system"
	StartedAt      *time.Time `json:"started_at,omitempty" bson:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty" bson:"completed_at,omitempty"`
	StatusReason   string     `json:"status_reason,omitempty" bson:"status_reason,omitempty"` // Why a scan ended "failed", e.g. "interrupted_by_restart"
	LastActivityAt *time.Time `json:"last_activity_at,omitempty" bson:"last_activity_at,omitempty"` // Updated by ingestion services on each batch
	// CompletionReason is how the scan was closed: ScanCompletion* or ScanReasonInterruptedByRestart.
	CompletionReason string `json:"completion_reason,omitempty" bson:"completion_reason,omitempty"`
	// FindingsReconciled is true when the scan drained (pipeline_quiescent) and no asset was
	// degraded. False for a partial scan: a timeout close (nothing resolved), or a scan with
	// DegradedAssets. The web app labels the latter partial. Nil on scans closed before the
	// field existed. Resolution itself depends only on positive evidence (scan_coverage).
	FindingsReconciled *bool `json:"findings_reconciled,omitempty" bson:"findings_reconciled,omitempty"`
	// DegradedAssets is added to by ingestion ($addToSet) when domain discovery reports that
	// it could not fully see a root domain asset.
	DegradedAssets []DegradedAsset `json:"degraded_assets,omitempty" bson:"degraded_assets,omitempty"`
	// UncheckedFindingIDs are the open findings that this scan did not see and left open
	// because it had no positive evidence that they are gone (the check of their target did
	// not run or not complete, or the host was not seen). Written by the scan monitor at close.
	UncheckedFindingIDs []string `json:"unchecked_finding_ids,omitempty" bson:"unchecked_finding_ids,omitempty"`
	CreatedAt      time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" bson:"updated_at"`

	// Assets that were targeted for scanning (input)
	TargetedAssets []AssetTarget `json:"targeted_assets,omitempty" bson:"targeted_assets,omitempty"`

	// Scan statistics (populated as scan progresses)
	Stats ScanStats `json:"stats,omitempty" bson:"stats,omitempty"`
}

// ScanStats tracks statistics for a scan execution
type ScanStats struct {
	TotalAssets         int `json:"total_assets" bson:"total_assets"`
	TotalDiscoveries    int `json:"total_discoveries" bson:"total_discoveries"`
	NewDiscoveries      int `json:"new_discoveries" bson:"new_discoveries"`
	ResolvedDiscoveries int `json:"resolved_discoveries" bson:"resolved_discoveries"`
	TotalFindings       int `json:"total_findings" bson:"total_findings"`
	NewFindings         int `json:"new_findings" bson:"new_findings"`
	ResolvedFindings    int `json:"resolved_findings" bson:"resolved_findings"`
	// UncheckedFindings: open findings this scan did not see and could not resolve, because
	// it had no positive evidence that they are gone (see Scan.UncheckedFindingIDs).
	UncheckedFindings int `json:"unchecked_findings" bson:"unchecked_findings"`
}

// AssetTarget represents an asset that was targeted for scanning
// Stored in Scan.TargetedAssets array for audit trail
type AssetTarget struct {
	AssetID string `json:"asset_id" bson:"asset_id"` // References assets._id
	Type    string `json:"type" bson:"type"`         // "domain" or "ip"
	Value   string `json:"value" bson:"value"`       // Domain name or IP address
}

// KBGenerationJob represents a job to generate a knowledge base entry for a finding type
// Published to kb_generation_queue by findings_ingestion when a new finding_type is encountered
// that doesn't already have a KB entry
type KBGenerationJob struct {
	FindingType  string                 `json:"finding_type" bson:"finding_type"`             // Unique finding type identifier
	Title        string                 `json:"title" bson:"title"`                           // Representative title for this finding type
	Severity     string                 `json:"severity" bson:"severity"`                     // Finding severity
	Source       string                 `json:"source" bson:"source"`                         // Source that produced the finding
	Description  string                 `json:"description" bson:"description"`               // Finding description
	Metadata     map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"` // Scanner-specific data
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"` // W3C TraceContext headers for span linking (not stored in DB)
	Created      time.Time              `json:"created" bson:"created"`
}

// KBGenerationResult represents a generated knowledge base entry
// Published to kb_generation_results by the knowledge-base-engine
type KBGenerationResult struct {
	FindingType  string                 `json:"finding_type" bson:"finding_type"`
	Entry        map[string]interface{} `json:"entry" bson:"entry"`               // Structured KB entry (business + technical content)
	Model        string                 `json:"model" bson:"model"`               // Model used for generation
	TraceID      string                 `json:"trace_id" bson:"trace_id"`
	TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"` // W3C TraceContext headers for span linking (not stored in DB)
	Timestamp    time.Time              `json:"timestamp" bson:"timestamp"`
}

