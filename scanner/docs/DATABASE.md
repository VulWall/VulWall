# Database

## Collections Overview

| Collection | Constant | Purpose | Writer |
|------------|----------|---------|--------|
| `assets` | `CollectionAssets` | User-added assets to scan (managed via UI) | Dashboard |
| `discoveries` | `CollectionDiscoveries` | Org-scoped scan results (4 asset types) | Ingestion |
| `findings` | `CollectionFindings` | Security vulnerabilities from scanners | Ingestion |
| `knowledge_base` | `CollectionKnowledgeBase` | Shared KB entries by finding_type (~84 entries) | Ingestion |
| `organizations` | `CollectionOrganizations` | Org settings with the scan schedule (`scan_settings`) | Dashboard |
| `scans` | `CollectionScans` | Scan execution records | Scan coordinator |

---

## Shared Go Models

### Job Models (Input)

**DiscoveryJob** — domain discovery jobs:
```go
type DiscoveryJob struct {
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    ScanID       *string                `json:"scan_id,omitempty"`
    OrgID        string                 `json:"org_id"`       // REQUIRED
    ParentID     *string                `json:"parent_id,omitempty"`
    Host         string                 `json:"host"`
    Port         *int                   `json:"port,omitempty"`
    Protocol     *string                `json:"protocol,omitempty"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
    Created      time.Time              `json:"created"`
}
```

**IPDiscoveryJob** — port discovery jobs:
```go
type IPDiscoveryJob struct {
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    ScanID       *string                `json:"scan_id,omitempty"`
    OrgID        string                 `json:"org_id"`            // REQUIRED
    ParentID     *string                `json:"parent_id,omitempty"`
    IP           string                 `json:"ip"`
    TargetDomain string                 `json:"target_domain,omitempty"` // Domain that resolved to this IP (for CDN ownership checks)
    PortRange    *string                `json:"port_range,omitempty"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
    Created      time.Time              `json:"created"`
}
```

### Finding Models (Output)

**DiscoveryFinding** — domain discovery findings:
```go
type DiscoveryFinding struct {
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    ScanID       *string                `json:"scan_id,omitempty"`
    OrgID        string                 `json:"org_id"`       // REQUIRED
    Source       string                 `json:"source"`       // REQUIRED: "subfinder", etc.
    ParentID     *string                `json:"parent_id,omitempty"`
    Host         string                 `json:"host"`
    IP           *string                `json:"ip,omitempty"`
    Port         *int                   `json:"port,omitempty"`
    Protocol     *string                `json:"protocol,omitempty"`
    Status       string                 `json:"status"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
    Timestamp    time.Time              `json:"timestamp"`
}
```

**IPDiscoveryFinding** — port discovery findings:
```go
type IPDiscoveryFinding struct {
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    ScanID       *string                `json:"scan_id,omitempty"`
    OrgID        string                 `json:"org_id"`       // REQUIRED
    Source       string                 `json:"source"`       // REQUIRED: "port_discovery", etc.
    ParentID     *string                `json:"parent_id,omitempty"`
    IP           string                 `json:"ip"`
    Port         int                    `json:"port"`
    Protocol     string                 `json:"protocol"`
    Status       string                 `json:"status"`
    Banner       *string                `json:"banner,omitempty"`
    ServiceName  *string                `json:"service_name,omitempty"`
    Product      *string                `json:"product,omitempty"`
    Version      *string                `json:"version,omitempty"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
    Timestamp    time.Time              `json:"timestamp"`
}
```

**SecurityFinding** — security vulnerabilities:
```go
type SecurityFinding struct {
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    ScanID       *string                `json:"scan_id,omitempty"`
    OrgID        string                 `json:"org_id"`       // REQUIRED
    Source       string                 `json:"source"`       // REQUIRED: "nuclei", etc.
    DiscoveryID  string                 `json:"discovery_id"`
    FindingType  string                 `json:"finding_type"`
    Severity     string                 `json:"severity"`     // info, low, medium, high, critical
    Title        string                 `json:"title"`
    Description  string                 `json:"description"`
    Remediation  string                 `json:"remediation,omitempty"` // only when the scanner provides it
    References   []string               `json:"references,omitempty"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
    Status       string                 `json:"status"`       // open, resolved
    Timestamp    time.Time              `json:"timestamp"`
}
```

**EnrichmentFinding** — discovery enrichment data:
```go
type EnrichmentFinding struct {
    TraceID        string                 `json:"trace_id"`
    TraceContext   map[string]string      `json:"trace_context,omitempty" bson:"-"`
    ScanID         *string                `json:"scan_id,omitempty"`
    OrgID          string                 `json:"org_id"`
    Source         string                 `json:"source"`         // "discovery_enrichment"
    DiscoveryID    string                 `json:"discovery_id"`
    EnrichmentType string                 `json:"enrichment_type"` // "waf", "geolocation"
    Data           map[string]interface{} `json:"data"`
    Timestamp      time.Time              `json:"timestamp"`
}
```

### Knowledge Base Models

**KBGenerationJob** — published by findings_ingestion for new finding_types:
```go
type KBGenerationJob struct {
    FindingType  string                 `json:"finding_type"`
    Title        string                 `json:"title"`
    Severity     string                 `json:"severity"`
    Source       string                 `json:"source"`
    Description  string                 `json:"description"`
    Metadata     map[string]interface{} `json:"metadata,omitempty"`
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    Created      time.Time              `json:"created"`
}
```

**KBGenerationResult** — published by knowledge-base-engine after Anthropic API call:
```go
type KBGenerationResult struct {
    FindingType  string                 `json:"finding_type"`
    Entry        map[string]interface{} `json:"entry"`        // Structured KB entry (business + technical content)
    Model        string                 `json:"model"`
    TraceID      string                 `json:"trace_id"`
    TraceContext map[string]string      `json:"trace_context,omitempty" bson:"-"`
    Timestamp    time.Time              `json:"timestamp"`
}
```

### Asset Models

**Asset** — user-added assets (read by scan-coordinator):
```go
type Asset struct {
    ID            string     `bson:"_id"`
    OrgID         string     `bson:"org_id"`
    Type          string     `bson:"type"`          // "domain" or "ip"
    Enabled       bool       `bson:"enabled"`
    DNSVerifiedAt *time.Time `bson:"dns_verified_at,omitempty"`
    Domain        *string    `bson:"domain,omitempty"`
    IP            *string    `bson:"ip,omitempty"`
    AddedOn       time.Time  `bson:"added_on"`
}
```

**Discovery** — unified scan result model (type discrimination via `asset_type`):
```go
type Discovery struct {
    ID              string                    `bson:"_id"`
    OrgID           string                    `bson:"org_id"`
    ScanIDs         []string                  `bson:"scan_ids"`
    AssetType       string                    `bson:"asset_type"`       // domain, subdomain, ip, port
    Source          string                    `bson:"source"`
    Status          string                    `bson:"status"`           // active, inactive, unknown
    OwnershipStatus string                    `bson:"ownership_status"` // verified, notMine, notSure
    DiscoveredAt    time.Time                 `bson:"discovered_at"`
    ParentID        *string                   `bson:"parent_id,omitempty"`
    FirstSeen       time.Time                 `bson:"first_seen"`
    LastSeen        time.Time                 `bson:"last_seen"`
    Metadata        map[string]interface{}    `bson:"metadata"`

    // Domain/Subdomain fields
    Domain            *string                  `bson:"domain,omitempty"`
    Subdomain         *string                  `bson:"subdomain,omitempty"`
    ResolutionHistory []ResolutionHistoryEntry  `bson:"resolution_history,omitempty"`

    // IP fields
    IP *string `bson:"ip,omitempty"`

    // Port fields
    Port             *int                   `bson:"port,omitempty"`
    Protocol         *string                `bson:"protocol,omitempty"`
    Banner           *string                `bson:"banner,omitempty"`
    ServiceName      *string                `bson:"service_name,omitempty"`
    Product          *string                `bson:"product,omitempty"`
    Version          *string                `bson:"version,omitempty"`
    PreviousServices []ServiceHistoryEntry  `bson:"previous_services,omitempty"`
}
```

### Scan/Organization Models

```go
type Organization struct {
    ID           string       `bson:"_id"`
    UserIDs      []string     `bson:"user_ids"`
    CompanyName  string       `bson:"company_name"`
    Industry     string       `bson:"industry"`
    Website      string       `bson:"website"`
    CreatedAt    time.Time    `bson:"created_at"`
    UpdatedAt    time.Time    `bson:"updated_at"`
    ScanSettings ScanSettings `bson:"scan_settings"`
}

type ScanSettings struct {
    ScanCron string `bson:"scan_cron"`         // 5-field cron in UTC (e.g., "0 2 * * *")
    Enabled  *bool  `bson:"enabled,omitempty"` // false = no scheduled scans; missing = on
}

type Scan struct {
    ID             string        `bson:"_id"`
    OrgID          string        `bson:"org_id"`
    Status         string        `bson:"status"`       // queued, pending, running, done, failed
    Type           string        `bson:"type"`          // scheduled, requested
    TriggeredBy    string        `bson:"triggered_by"`  // user ID or "system"
    StartedAt      *time.Time    `bson:"started_at,omitempty"`
    CompletedAt    *time.Time    `bson:"completed_at,omitempty"`
    StatusReason   string        `bson:"status_reason,omitempty"` // why a scan is "failed", e.g. "interrupted_by_restart"
    CompletionReason   string    `bson:"completion_reason,omitempty"`   // pipeline_quiescent, idle_timeout, safety_timeout, interrupted_by_restart
    FindingsReconciled *bool     `bson:"findings_reconciled,omitempty"` // true only when the close resolved every open finding it did not see, for every asset
    DegradedAssets     []DegradedAsset `bson:"degraded_assets,omitempty"` // root domain assets discovery could not fully see ($addToSet by domain ingestion)
    UncheckedFindingIDs []string `bson:"unchecked_finding_ids,omitempty"` // open findings not seen and left open because their asset is degraded
    CreatedAt      time.Time     `bson:"created_at"`
    UpdatedAt      time.Time     `bson:"updated_at"`
    TargetedAssets []AssetTarget `bson:"targeted_assets"`
    Stats          ScanStats     `bson:"stats"`
}

type DegradedAsset struct {
    AssetID string `bson:"asset_id,omitempty"` // assets._id (empty for jobs from older versions)
    Domain  string `bson:"domain"`             // the root domain as scanned
    Reason  string `bson:"reason"`             // root_nxdomain, dns_failures, subdomain_enumeration_failed
}

type AssetTarget struct {
    AssetID string `bson:"asset_id"`
    Type    string `bson:"type"`   // "domain" or "ip"
    Value   string `bson:"value"`  // domain name or IP address
}

type ScanStats struct {
    TotalAssets         int `bson:"total_assets"`
    TotalDiscoveries    int `bson:"total_discoveries"`
    NewDiscoveries      int `bson:"new_discoveries"`
    ResolvedDiscoveries int `bson:"resolved_discoveries"`
    TotalFindings       int `bson:"total_findings"`
    NewFindings         int `bson:"new_findings"`
    ResolvedFindings    int `bson:"resolved_findings"`
}
```

---

## MongoDB Document Schemas

### Assets Collection
```javascript
{
  _id: ObjectId("..."),
  org_id: "507f1f77bcf86cd799439011",
  type: "domain",                    // "domain" or "ip"
  enabled: true,
  dns_verified_at: ISODate("2025-11-09T08:53:38.744Z"),
  domain: "moj.dev",                // For domain assets
  added_on: ISODate("2025-11-09T08:53:27.775Z")
}
```

### Discoveries Collection
```javascript
// Domain with enrichment
{
  _id: "uuid-123",
  org_id: "org-456",
  scan_ids: ["scan-abc-456", "scan-xyz-789"],
  asset_type: "domain",
  source: "subfinder",
  status: "active",
  ownership_status: "verified",
  domain: "example.com",
  resolution_history: [
    { ip: "93.184.216.34", first_seen: ISODate("..."), last_seen: null }
  ],
  metadata: {
    waf: "Cloudflare",
    geo: { continent: "North America", country: "United States", isp: "Cloudflare, Inc." }
  },
  first_seen: ISODate("..."),
  last_seen: ISODate("...")
}

// Port with service tracking
{
  _id: "uuid-456",
  org_id: "org-456",
  scan_ids: ["scan-abc-456"],
  asset_type: "port",
  source: "port_discovery",
  status: "active",
  ownership_status: "verified",
  parent_id: "ip-uuid",
  port: 443,
  protocol: "tcp",
  service_name: "https",
  product: "nginx",
  version: "1.21.0",
  previous_services: [
    { service_name: "https", product: "Apache", version: "2.4.41", last_seen: ISODate("...") }
  ]
}
```

### Findings Collection
```javascript
{
  _id: "uuid",
  org_id: "uuid",
  discovery_id: "uuid",
  finding_type: "cve-2024-1234",
  severity: "critical",
  source: "nuclei",
  title: "Remote Code Execution",
  description: "...",
  remediation: "...",            // optional
  references: ["https://..."],   // optional
  metadata: { /* scanner-specific */ },
  status: "open",
  scan_ids: ["scan-abc-456"],
  first_detected: ISODate("..."),
  last_detected: ISODate("..."),
  resolved_at: null
}
```

#### Finding text written by the scanners

Each finding carries the scanner's own human-readable text, so the web app can
show it without a knowledge-base entry (the KB engine is optional and only runs
when `ANTHROPIC_API_KEY` is set). Empty values are not written, and an update
never clears text that an earlier scan stored.

| Field | Type | nuclei | testssl | jsscanner (retire.js) | http-headers | email-security |
|-------|------|--------|---------|-----------------------|--------------|----------------|
| `title` | string | `info.name` | `TLS/SSL: <test id>` | component, version, summary, CVEs | rule title | check title |
| `description` | string | `info.description` | testssl `finding` text | advisory summary | rule explanation | check explanation |
| `remediation` | string, optional | `info.remediation` | — | — | — | — |
| `references` | string array, optional | `info.reference` | — | advisory URLs | MDN / OWASP URLs | RFC / guide URLs |

The same URLs also stay in `metadata.reference` (nuclei) and
`metadata.references` (other scanners) for backward compatibility; new readers
should use the top-level `references` field.

### Knowledge Base Collection
```javascript
// One entry per unique finding_type (~84 entries), shared across all orgs
// _id = "kb_" + finding_type (e.g., "kb_cve-2024-1234")
{
  _id: "kb_cve-2024-1234",
  finding_type: "cve-2024-1234",
  business: {
    title: "Critical Security Vulnerability in...",
    summary: "A brief explanation for non-technical stakeholders...",
    impact: "Potential business impact...",
    urgency: "immediate",
    actions: ["Action 1", "Action 2"],
    blog_slug: "cve-2024-1234-what-businesses-need-to-know"
  },
  technical: {
    title: "CVE-2024-1234: Remote Code Execution",
    vulnerability_explanation: "Detailed technical explanation...",
    root_cause: "The underlying cause...",
    impact: "Technical impact assessment...",
    severity: { level: "critical", cvss_score: 9.8, vector: "CVSS:3.1/..." },
    affected_versions: "< 1.10.23",
    remediation_steps: ["Step 1", "Step 2", "Step 3"],
    verification_steps: ["Verify 1", "Verify 2"],
    code_examples: { vulnerable: "...", fixed: "..." },
    best_practices: ["Practice 1", "Practice 2"],
    references: ["https://..."],
    blog_slug: "cve-2024-1234-technical-remediation-guide"
  },
  metadata: {
    components: ["component-name"],
    owasp_category: "A03:2021 - Injection",
    estimated_effort: "medium",
    is_exploitable: true,
    tags: ["rce", "critical"]
  },
  model: "claude-sonnet-4-5-20250514",
  created_at: ISODate("..."),
  updated_at: ISODate("...")
}
```

### Scans Collection

**Lifecycle.** Two writers create scans:

- **Requested scans** — the web app inserts
  `{_id, org_id, status: "queued", triggered_by, created_at}`. The scan
  coordinator polls every 5 s and claims the document in place: it sets
  `status: "running"`, `type: "requested"`, `started_at`, `updated_at`,
  `targeted_assets` and `stats.total_assets`, then publishes discovery jobs
  with that `_id`.
- **Scheduled scans** — the coordinator's cron inserts a new document with
  `status: "running"` and `started_at`.

Status values: `queued` → `running` → `done` (or `failed`). `pending` is still
read by the guards for older documents but is no longer written.

- One active scan per organization. A queued scan waits while its organization
  has a `pending` or `running` scan and starts on a later poll. Only the oldest
  queued scan of an organization starts in one poll, so several queued
  requests run one after another.
- A scheduled trigger is skipped while the organization has a `queued`,
  `pending` or `running` scan.
- A queued scan whose organization does not exist becomes `failed`. A queued
  scan with no enabled assets becomes `done` at once, with
  `findings_reconciled: false`. If no discovery job can
  be published, the scan becomes `failed`. Each of these sets `completed_at`.
- The scan monitor sets `status: "done"`, `completed_at`, `completion_reason`,
  `findings_reconciled` and the `stats.*` counters when the pipeline is drained
  (`pipeline_quiescent`) or a timeout fires (`idle_timeout`, `safety_timeout`).
  Scan age for the completion timeouts is measured from `started_at` (from
  `created_at` when `started_at` is absent).
- Only a `pipeline_quiescent` close of a scan with at least one discovery
  resolves findings: every open finding of the organization that the scan did
  not see, except those under an asset in `degraded_assets` (written to
  `unchecked_finding_ids`). `findings_reconciled` is `true` only when nothing was
  degraded. Any other close leaves findings untouched and writes
  `findings_reconciled: false` and `stats.resolved_findings: 0`.
- The `new_*` and `resolved_discoveries` counters compare with the previous
  `done` scan that has `findings_reconciled` not `false`, or that drained with
  `degraded_assets`. Scans closed before these fields existed have none of them
  and still count.
- Domain ingestion adds an entry to `degraded_assets` when domain discovery
  reports that it could not fully see a root domain asset (`root_nxdomain`,
  `dns_failures`, `subdomain_enumeration_failed`). See
  [ARCHITECTURE.md](ARCHITECTURE.md) (scan completion and finding resolution).
- When the scanner starts, before the scan monitor runs, every `pending` or
  `running` scan becomes `failed` with `status_reason` and `completion_reason`
  `"interrupted_by_restart"`, `findings_reconciled: false` and `completed_at`. The restart lost the scan's in-flight work, so the scan
  does not resolve findings and is not used as the baseline of the next scan.
  Findings it already wrote stay as they are. Queued scans are not touched.
  Right after that, the scanner removes the previous process's consumers from
  every group it consumes (`ownedGroups()`) with their pending entries:
  nothing would ever redeliver them, and in the scan-pipeline groups they would
  keep the pipeline from looking quiescent.
  This assumes one scanner process per database and Redis.
- The scan monitor only writes `done` while the scan is still `pending` or
  `running`, so it never reopens a scan that was closed as `failed`.

```javascript
{
  _id: "scan-uuid-456",
  org_id: "org-uuid-123",
  status: "running",
  type: "scheduled",
  triggered_by: "system",
  started_at: ISODate("..."),
  completed_at: null,
  created_at: ISODate("..."),
  updated_at: ISODate("..."),
  targeted_assets: [
    { asset_id: "asset-uuid-1", type: "domain", value: "example.com" },
    { asset_id: "asset-uuid-2", type: "ip", value: "192.168.1.100" }
  ],
  stats: {
    total_assets: 2,
    total_discoveries: 15,
    new_discoveries: 3,
    resolved_discoveries: 1,
    total_findings: 8,
    new_findings: 2,
    resolved_findings: 0
  }
}
```

### Organizations Collection
```javascript
{
  _id: "org-uuid-123",
  user_ids: ["user-1", "user-2"],
  company_name: "Example Corp",
  industry: "Technology",
  website: "https://example.com",
  created_at: ISODate("..."),
  updated_at: ISODate("..."),
  scan_settings: {
    scan_cron: "0 2 * * *",       // Daily at 02:00 UTC (5-field: min hour day month weekday)
    enabled: true,                // false turns scheduled scans off
    timezone: "Europe/Amsterdam"  // Web app only: the zone the Settings form shows the time in
  }
}
```

---

## Query Examples

### Asset Queries

```javascript
// All assets for an org
db.discoveries.find({ org_id: "org-uuid" })

// Only ports
db.discoveries.find({ org_id: "org-uuid", asset_type: "port" })

// Verified assets
db.discoveries.find({ org_id: "org-uuid", ownership_status: "verified" })

// Domain hierarchy: subdomains of a domain
db.discoveries.find({ org_id: "org-uuid", asset_type: "subdomain", parent_id: "domain-uuid" })

// IPs of a domain/subdomain
db.discoveries.find({ org_id: "org-uuid", asset_type: "ip", parent_id: "domain-uuid" })

// Ports on an IP
db.discoveries.find({ org_id: "org-uuid", asset_type: "port", parent_id: "ip-uuid" })
```

### Enrichment Queries

```javascript
// Assets with specific WAF
db.discoveries.find({ org_id: "org-uuid", "metadata.waf": "Cloudflare" })

// Unprotected assets (no WAF)
db.discoveries.find({
  org_id: "org-uuid",
  asset_type: { $in: ["domain", "subdomain"] },
  $or: [{ "metadata.waf": { $exists: false } }, { "metadata.waf": null }]
})

// Assets by country
db.discoveries.find({ org_id: "org-uuid", "metadata.geo.country": "United States" })
```

### Scan Queries

```javascript
// Discoveries from a specific scan
db.discoveries.find({ org_id: "org-uuid", scan_ids: "scan-abc-456" })

// Count by asset type per scan
db.discoveries.aggregate([
  { $match: { org_id: "org-uuid", scan_ids: "scan-abc-456" } },
  { $group: { _id: "$asset_type", count: { $sum: 1 } } }
])

// Assets in multiple scans (intersection)
db.discoveries.find({ org_id: "org-uuid", scan_ids: { $all: ["scan-1", "scan-2"] } })

// All scans for an org
db.scans.find({ org_id: "org-uuid" }).sort({ created_at: -1 })

// Findings from a scan
db.findings.find({ org_id: "org-uuid", scan_ids: "scan-abc-456" })
```

### Redis CLI Job Publishing

```bash
# Domain discovery job (with scan_id)
redis-cli XADD domain_discovery_queue * data '{
  "trace_id": "trace-123",
  "scan_id": "scan-abc-456",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "example.com",
  "created": "2025-10-15T10:00:00Z"
}'

# Port discovery job
redis-cli XADD ip_discovery_queue * data '{
  "trace_id": "trace-456",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip": "8.8.8.8",
  "created": "2025-10-15T10:00:00Z"
}'
```

---

## Validation Rules

- **org_id REQUIRED** — all jobs and findings must include `org_id` or they are skipped
- **source REQUIRED** — ingestion skips findings without `source` field
- **Dedup keys:** findings deduplicated by `(org_id, discovery_id, finding_type, title)`
- **Scan tracking:** `scan_ids` array uses MongoDB `$addToSet` to prevent duplicates
- **History:** IP resolution history and service history tracked via arrays, not overwrite
