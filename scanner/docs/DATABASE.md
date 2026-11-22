# Database

## Collections Overview

| Collection | Constant | Purpose | Writer |
|------------|----------|---------|--------|
| `assets` | `CollectionAssets` | User-added assets to scan (managed via UI) | Dashboard |
| `discoveries` | `CollectionDiscoveries` | Org-scoped scan results (4 asset types) | Ingestion (the web app removes them on asset delete) |
| `findings` | `CollectionFindings` | Security vulnerabilities from scanners | Ingestion (the scan monitor resolves; the web app removes them on asset delete) |
| `scan_coverage` | `CollectionScanCoverage` | Per-scan evidence that a check completed on a target, or that a host is gone | Ingestion (the web app removes them on asset delete) |
| `knowledge_base` | `CollectionKnowledgeBase` | Shared KB entries by finding_type (~84 entries) | Ingestion |
| `organizations` | `CollectionOrganizations` | Org settings with the scan schedule (`scan_settings`) | Dashboard |
| `scans` | `CollectionScans` | Scan execution records | Scan coordinator |
| `demo_seed` | `demoseed` (unexported) | Only after `demo-seed` ran: per seeded organization (`_id` = the organization's `_id`), the `company_name`, `industry`, `website`, `scan_settings` and `tour_completed` it replaced, for `demo-seed --reset` | `demo-seed` |
| `system_info` | `sysinfo.Collection` | Versions of the scanner and its tools, for the web app's About dialog (one document, `_id: "scanner"`) | `sysinfo` (scanner start-up, then every 5 min) |

Sample data: `demo-seed` (`src/cmd/demo-seed`, `src/internal/demoseed`) inserts documents with
the shapes below into `assets`, `discoveries`, `findings`, `scans`, `scan_coverage`,
`system_info` and `knowledge_base` (only where the document is missing; published entries for
the top demo finding types, `model: "demo-seed (sample entry)"`) and the web app's
`finding_suppressions`, each with an extra
`demo: true`. `demo-seed --reset` deletes exactly those and restores the organization from
`demo_seed`. Nothing else writes or reads the `demo` field.

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
    KnownSubdomains []string            `json:"known_subdomains,omitempty"` // names below Host seen in the last 90 days (coordinator)
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
    Coverage     *ScanCoverage          `json:"coverage,omitempty" bson:"-"` // set: not a finding, see below
}

// ScanCoverage is evidence about one target in one scan (stored in scan_coverage).
type ScanCoverage struct {
    Source      string       `json:"source"`       // finding source, or "domain_discovery" / "port_discovery"
    DiscoveryID string       `json:"discovery_id"`
    Target      string       `json:"target,omitempty"`
    Status      string       `json:"status"`       // ok, error, absent
    Error       string       `json:"error,omitempty"`
    Reported    []FindingKey `json:"reported,omitempty"` // {finding_type, title} of every finding reported
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
    AssetIDs        []string                  `bson:"asset_ids,omitempty"` // assets._id (hex) whose scans reached it
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
    FindingsReconciled *bool     `bson:"findings_reconciled,omitempty"` // true for a pipeline_quiescent close with no degraded_assets (display flag)
    DegradedAssets     []DegradedAsset `bson:"degraded_assets,omitempty"` // root domain assets discovery could not fully see ($addToSet by domain ingestion; information only)
    UncheckedFindingIDs []string `bson:"unchecked_finding_ids,omitempty"` // open findings not seen and left open: no positive evidence they are gone
    CreatedAt      time.Time     `bson:"created_at"`
    UpdatedAt      time.Time     `bson:"updated_at"`
    TargetedAssets []AssetTarget `bson:"targeted_assets"`
    Stats          ScanStats     `bson:"stats"`
}

type DegradedAsset struct {
    AssetID string `bson:"asset_id,omitempty"` // assets._id (empty for jobs from older versions)
    Domain  string `bson:"domain"`             // the root domain as scanned
    Reason  string `bson:"reason"`             // root_nxdomain, dns_failures, publish_failed, subdomain_enumeration_failed
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
  asset_ids: ["507f1f77bcf86cd799439012"],
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

`asset_ids` lists the assets (`assets._id`, hex) whose scans reached the discovery. The scanner
only adds to it (`$addToSet`) and never writes an empty list: it leaves the field out instead.
The three states:

- **Missing:** written before ownership was recorded. Shown by the web app, and in scope of
  every scan's finding resolution.
- **Ids:** shown while one of them is an enabled asset. Finding resolution skips the discovery
  when the scan targeted none of them.
- **Empty (`[]`):** only the web app writes it, while it deletes the discovery's last asset.
  Hidden by the web app and skipped by finding resolution, like a discovery of a disabled asset.

When the user deletes an asset, the web app first disables it and checks again that no scan
started (a scan that read the asset before the disable is seen by that check, and the delete
stops with the asset disabled). Then:

1. It removes the id from `asset_ids` (`$pull`) in every discovery of the organization.
2. Discoveries whose `asset_ids` is now empty belong to no asset. Per batch, the web app checks
   again that they are still empty (a scan may have added an owner back), deletes their
   `findings`, `finding_suppressions` and `scan_coverage` records (by `discovery_id`), removes
   `parent_id` from the owned discoveries that point at one of them, and then deletes them.
   Discoveries that another asset also reaches keep their data, and so do discoveries without
   `asset_ids`.
3. It deletes the asset last. `scans` (`targeted_assets`, `unchecked_finding_ids`) and
   `knowledge_base` are kept, so a scan can name findings that no longer exist.

Because the scanner never writes an empty `asset_ids`, an empty one means "delete pending", and
deleting the asset again finishes a run that stopped part-way. When a later scan finds a
subdomain or IP under a parent again, domain ingestion sets its missing `parent_id`.

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
  resolved_at: null,             // set with status "resolved"
  resolved_by_scan_id: null,     // the scan that resolved it
  resolution_reason: null        // "not_reproduced" | "host_no_longer_found"
}
```

A finding is resolved only by the scan monitor, only at a `pipeline_quiescent` close, and only
on positive evidence (`resolution_reason`): `not_reproduced` (its host was re-discovered, its
scanner completed on it and did not report it) or `host_no_longer_found` (its host was confirmed
gone in 3 consecutive drained scans). See [ARCHITECTURE.md](ARCHITECTURE.md) (scan completion
and finding resolution). When a scan reports the finding again, ingestion reopens it and removes
`resolved_at`, `resolved_by_scan_id` and `resolution_reason`.

### scan_coverage Collection

One record per `(scan_id, source, discovery_id)` (unique index), written by
`findings_ingestion` from the coverage messages that scanners and discovery publish on
`security_findings` (`shared.ScanCoverage`, carried in `SecurityFinding.coverage`):

```javascript
{
  _id: ObjectId("..."),
  scan_id: "scan-uuid",
  org_id: "org-uuid",
  source: "http-headers",        // a finding source, or "domain_discovery" / "port_discovery"
  discovery_id: "uuid",          // the target; for port_discovery, the IP discovery
  target: "www.example.com",     // what was checked (for people)
  status: "ok",                  // "ok" | "error" | "absent" (domain_discovery only)
  error: "...",                  // why the check did not complete (status "error")
  reported: [                    // scanners, status "ok": every finding the check reported
    { finding_type: "missing-hsts", title: "Missing Strict-Transport-Security (HSTS) header" }
  ],
  created_at: ISODate("..."),
  updated_at: ISODate("...")
}
```

- Two runs for the same key in one scan (a redelivered message, or a host that is both an asset
  and a subdomain of another asset) merge: `error` sticks, `reported` is the union.
- Retention: a TTL index removes records 90 days after `created_at`
  (`mongox.ScanCoverageRetention`). Resolution reads the closing scan's records and, for
  `host_no_longer_found`, those of the organization's last 3 drained scans, so scans more than
  90 days apart cannot confirm a host gone (its findings then stay open).
- Indexes: `idx_scan_source_discovery` (unique), `idx_org_discovery_source_time`, `ttl_created_at`
  (created at startup by `mongox.EnsureIndexes`).

#### Finding text written by the scanners

Each finding carries the scanner's own human-readable text, so the web app can
show it without a knowledge-base entry (the KB engine is optional and only runs
when `ANTHROPIC_API_KEY` is set). Empty values are not written, and an update
never clears text that an earlier scan stored.

| Field | Type | nuclei | testssl | certificate | jsscanner (retire.js) | http-headers | email-security |
|-------|------|--------|---------|-------------|-----------------------|--------------|----------------|
| `title` | string | `info.name` | `TLS/SSL: <test id>` | `TLS certificate expires soon: <host>` / `TLS certificate expired: <host>` | component, version, summary, CVEs | rule title | check title |
| `description` | string | `info.description` | testssl `finding` text | expiry date, days left, subject, issuer | advisory summary | rule explanation | check explanation |
| `remediation` | string, optional | `info.remediation` | — | renew / check ACME auto-renewal | — | — | — |
| `references` | string array, optional | `info.reference` | — | — | advisory URLs | MDN / OWASP URLs | RFC / guide URLs |

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
  `status: "running"`, `type` (`"scheduled"` for a scan the cron queued,
  else `"requested"`), `started_at` and `updated_at`,
  then reads the organization's assets (so an asset added while the scan was
  queued is in it), sets `targeted_assets` and `stats.total_assets`, and
  publishes discovery jobs with that `_id`. A failure after the claim marks
  the scan `failed`.
- **Scheduled scans** — the coordinator's cron inserts a new document with
  `status: "running"` and `started_at`. When the organization has a `pending`
  or `running` scan, it inserts a queued scan instead
  (`{_id, org_id, status: "queued", type: "scheduled", triggered_by: "system",
  created_at, updated_at}`), which the poller starts after the running scan.

Status values: `queued` → `running` → `done` (or `failed`). `pending` is still
read by the guards for older documents but is no longer written.

- One active scan per organization. A queued scan waits while its organization
  has a `pending` or `running` scan and starts on a later poll. Only the oldest
  queued scan of an organization starts in one poll, so several queued
  requests run one after another.
- A scheduled trigger is skipped while the organization has a `queued` scan:
  that scan reads the assets when it starts, so it covers them all. While a
  scan is `pending` or `running`, the trigger queues a scan (see above). The
  web app's unique partial index (`org_id_1_queued_unique`) allows one queued
  scan per organization; the coordinator reads a duplicate-key error on that
  insert as "already queued".
- A queued `scheduled` scan whose organization's schedule was turned off
  while it waited (`scan_settings.enabled: false` or no `scan_cron`) is
  deleted: it never started, so there is nothing to keep. The delete filters
  on `_id` and `status: "queued"`, so a scan claimed at the same time is not
  deleted. Requested scans do not depend on the schedule.
- A queued scan whose organization does not exist becomes `failed`. A queued
  scan with no enabled assets becomes `done` at once, with
  `findings_reconciled: false`. If no discovery job can
  be published, the scan becomes `failed`. Each of these sets `completed_at`.
- The scan monitor sets `status: "done"`, `completed_at`, `completion_reason`,
  `findings_reconciled` and the `stats.*` counters when the pipeline is drained
  (`pipeline_quiescent`) or a timeout fires (`idle_timeout`, `safety_timeout`).
  Scan age for the completion timeouts is measured from `started_at` (from
  `created_at` when `started_at` is absent).
- Only a `pipeline_quiescent` close resolves findings, and only those with
  positive evidence in `scan_coverage` (see the findings collection). The open
  findings the scan did not see and could not resolve are counted in
  `stats.unchecked_findings` and listed in `unchecked_finding_ids`.
  `findings_reconciled` is `true` for a `pipeline_quiescent` close with no
  `degraded_assets` (the web app labels the others "partial"). Any other close
  leaves findings untouched and writes `findings_reconciled: false` and
  `stats.resolved_findings: 0`.
- The `new_*` and `resolved_discoveries` counters compare with the previous
  `done` scan that closed `pipeline_quiescent`. Scans closed before
  `completion_reason` existed have no field and still count, unless they are
  the instant close of a scan with no assets (`findings_reconciled: false`).
- Domain ingestion adds an entry to `degraded_assets` when domain discovery
  reports that it could not fully see a root domain asset (`root_nxdomain`,
  `dns_failures`, `publish_failed`, `subdomain_enumeration_failed`). It is
  information for the user; resolution does not depend on it. See
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
    resolved_findings: 0,
    unchecked_findings: 3       // open findings not seen and not resolvable this scan
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
    timezone: "Europe/Amsterdam"  // Web app only: the browser zone the schedule was saved in; the Settings form shows the time in it
  }
}
```

### system_info Collection
Written by `internal/core/sysinfo` at start-up and every 5 minutes, every 30 s until the
templates version is known (`$set`, upsert). Not scan
data. The web app reads it and shows an empty or missing value as "unknown".
```javascript
{
  _id: "scanner",
  version: "v0.1.0",                 // VULWALL_VERSION (release tag; "dev" or "dev (<commit>)" for local builds)
  nuclei: "3.11.1",                  // NUCLEI_VERSION, pinned in scanner/Dockerfile
  nuclei_templates: "v10.5.2",       // from nuclei's .templates-config.json; "" before the first update
  nuclei_templates_updated_at: ISODate("..."), // mtime of <templates dir>/.checksum, or null
  testssl: "v3.2.5",                 // TESTSSL_VERSION, pinned in scanner/Dockerfile
  retire: "5.4.2",                   // installed retire package.json
  dbip_country_date: "2026-11-01",   // DB-IP Lite build date (MMDB metadata)
  dbip_asn_date: "2026-11-01",
  started_at: ISODate("..."),        // when this scanner process started
  updated_at: ISODate("...")
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
- **Ownership:** `asset_ids` holds every asset (`assets._id`, hex) whose scan reached the discovery. Jobs and findings carry `asset_id`; domain and port ingestion add it with `$addToSet`. A port gets its IP's list: the IP is port-scanned once per scan, so domain ingestion adds a later asset to the IP and then to the IP's ports, and port ingestion copies the IP's list onto a port it writes. The port scan of a direct IP asset also publishes an `ip` finding on every scan, also with no port open, and port ingestion adds the asset to the IP and all its ports the same way (it does not enrich the IP again). New discoveries hold the id in the insert itself
- **History:** IP resolution history and service history tracked via arrays, not overwrite
