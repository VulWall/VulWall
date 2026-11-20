# Architecture

## Overview

The VulWall scanner (formerly NightWatch) is a **vertically-sliced Go monorepo** for security scanning. Each feature domain is a separate package (a "component"), and all components run as goroutines in **one binary**, `nightwatch` (`src/cmd/nightwatch/main.go`). Components never call each other directly: they communicate only through Redis streams, so the pipeline behaves as it did when every component was its own service.

**Key principles:**
- **Vertical slice architecture** — each feature is self-contained
- **Centralized ingestion** — only the ingestion service writes to MongoDB
- **Redis Streams** — all inter-service communication via streams
- **Org-scoped** — every record includes `org_id`; jobs without it are skipped

**Two asset collections:**
- `assets` — user-added assets to scan (managed via UI, `enabled: true/false`)
- `discoveries` — scan results (auto-discovered, `ownership_status: verified/notMine/notSure`)

---

## Communication Flow

```
DOMAIN DISCOVERY FLOW:
1. Job → domain_discovery_queue (with org_id)
   └─→ Domain Discovery Service (subfinder)
       ├─→ Finds subdomains, resolves IPs
       └─→ Publishes to domain_discovery_results (source="subfinder")

2. Domain Ingestion Consumer
   └─→ Persists to discoveries collection (with org_id):
       ├─→ Domains/subdomains: tracks IP resolution history
       └─→ IPs: separate records with parent_id
   └─→ Publishes downstream:
       ├─→ ip_discovery_queue (triggers port scanning for new IPs)
       ├─→ discovery_enrichment_queue (WAF + geolocation)
       └─→ domain_scan_triggers (active recon scanners)

PORT DISCOVERY FLOW:
1. Job → ip_discovery_queue (with org_id)
   └─→ Port Discovery Service (TCP scanner; CDN IPs skipped via PTR check)
       └─→ Publishes to ip_discovery_results

2. Port Ingestion Consumer
   └─→ Persists ports to discoveries collection
   └─→ Publishes downstream:
       ├─→ discovery_enrichment_queue
       └─→ port_scan_triggers (active recon scanners)

SECURITY FINDINGS FLOW:
1. Active Recon Scanners consume from trigger streams:
   ├─→ domain_scan_triggers (domains/subdomains)
   └─→ port_scan_triggers (ports)

2. Scanners publish to security_findings stream

3. Findings Ingestion Consumer
   └─→ Persists to findings collection:
       ├─→ Deduplicates by (org_id, discovery_id, finding_type, title)
       ├─→ Updates last_detected on duplicates
       └─→ Reopens resolved findings if detected again
   └─→ For new finding_types: publishes to kb_generation_queue (Redis SETNX dedup lock)

DISCOVERY ENRICHMENT FLOW:
1. Discovery Enrichment Service consumes from discovery_enrichment_queue
2. Enriches by asset_type:
   ├─→ Domain/Subdomain: IP geolocation + WAF detection
   ├─→ IP: geolocation only
   └─→ Port: skipped
3. Publishes to discovery_enrichment_results

4. Enrichment Ingestion updates discoveries:
   ├─→ metadata.waf = "WAF_Name"
   └─→ metadata.geo.{continent, country, isp}

KNOWLEDGE BASE FLOW:
1. findings_ingestion checks if KB entry exists for finding_type (Redis SETNX lock + MongoDB check)
2. If new finding_type: publishes KBGenerationJob to kb_generation_queue
3. knowledge-base-engine calls Anthropic Claude API to generate business + technical KB content
4. Publishes KBGenerationResult to kb_generation_results
5. kb_ingestion upserts to knowledge_base collection (_id = "kb_" + findingType, $setOnInsert for idempotency)
6. The web app reads from knowledge_base collection (shared across all orgs, ~84 entries)

SCAN COORDINATOR FLOW:
1. Runs on cron schedule per organization (`scan_settings.scan_cron`, skipped when `scan_settings.enabled` is false)
2. Creates Scan record (status=running, type=scheduled)
3. Queries enabled user-added assets from assets collection
4. Publishes discovery jobs to Redis:
   ├─→ Domain assets → domain_discovery_queue
   └─→ IP assets → ip_discovery_queue
5. Scan monitor tracks completion via consumer group pending counts
```

---

## Model Ownership Rules

**Put in `src/internal/shared/models.go`** — models used by 2+ services:
- Job formats: `DiscoveryJob`, `IPDiscoveryJob`
- Finding formats: `DiscoveryFinding`, `IPDiscoveryFinding`, `SecurityFinding`, `EnrichmentFinding`
- KB formats: `KBGenerationJob`, `KBGenerationResult`
- Asset models: `Asset`, `Discovery`, `ResolutionHistoryEntry`, `ServiceHistoryEntry`
- Scan models: `Organization`, `ScanSettings`, `Scan`, `ScanStats`, `AssetTarget`

**Put in `src/internal/shared/constants.go`** — constants used by 2+ services:
- Stream names, collection names, asset types, severities, protocols, statuses

**Put in service directory** — models/constants used by only that service:
- Consumer group names → `constants.go`
- Scanner-specific models → `models.go`

**Rule:** If used by 2+ services → `shared/`. Otherwise → service directory.

---

## Discovery Service Pattern

Discovery services use a **parallel consumer group pattern** where multiple independent services listen to the same input stream with different consumer groups:

```
Input: domain_discovery_queue
    ├─→ Consumer Group: domain_discovery_service  → subfinder discovery + DNS resolution
    ├─→ Consumer Group: nmap_discovery_service     → Nmap (future)
    └─→ Consumer Group: masscan_discovery_service  → Masscan (future)
        ↓
    All publish to: domain_discovery_results
        ↓
    Ingestion Service → MongoDB
```

Benefits: components stay decoupled (Redis is the only interface), a single MongoDB writer, and simple operations: one process and one container image.

---

## Scan Coordinator Architecture

**Location:** `src/internal/scan_coordinator/`

**Components:**
- `scheduler.go` — cron-based scheduler using `robfig/cron/v3`
- `queued_scans.go` — polls MongoDB every 5 s for scans the web app queued and starts them
- `service.go` — core coordination logic (start scans, publish jobs, one-active-scan guard)
- `scan_monitor.go` — marks scans done when the pipeline has drained (see `pipeline.go`)
- `stream_cleanup.go` — trims result streams on schedule

The web app and the scanner share no HTTP API. The web app inserts a `scans`
document with `status: "queued"` and polls the document for `done`/`failed`.

**Cron schedules:**
- Per-org scan: `scan_settings.scan_cron` (5-field, UTC: `min hour day month weekday`). No scan when `scan_settings.enabled` is `false` or the cron is empty
- Org refresh: `*/5 * * * *` (every 5 minutes; only organizations whose schedule changed are rescheduled, and a failed load keeps the current schedules)
- Stream cleanup: `5 */6 * * *` (every 6 hours)
- Scan monitor: every 5 minutes
- Queued-scan poll: every 5 seconds (ticker, not cron)

**Scan lifecycle:**
1. Either the web app inserts a scan with status `queued` and the poller claims it in place (status `running`, `started_at` set), or the cron fires and the coordinator inserts a scan with status `running`
2. Query enabled assets → publish discovery jobs with the scan's `_id` as `scan_id`
3. Discovery → ingestion → active recon pipeline processes normally
4. Scan monitor checks the pipeline groups → marks the scan `done` when every group has drained (or a timeout fires)

**Scan completion and finding resolution.** Closing a scan as `done` can also resolve findings:
an open finding of the organization that this scan did not see is marked `resolved`. A false
resolution tells a customer that an unfixed vulnerability is fixed, so the monitor resolves
findings only for what it is sure the scan saw (`reconcileFindings()` in `scan_monitor.go`,
`findingsToResolve()` in `finding_resolution.go`). Each close writes `completion_reason` and
`findings_reconciled` on the scan (a queued scan with no enabled assets is closed `done` at once
with only `findings_reconciled: false`):

| `completion_reason` | When | Resolves findings |
|---------------------|------|-------------------|
| `pipeline_quiescent` | Past `ScanMinRuntime`, ingestion quiet for `ScanSettleGrace`, every scan-pipeline group drained | Yes, unless the scan has zero discoveries. Findings under a degraded asset stay open |
| `idle_timeout` | No ingestion activity for `ScanIdleTimeout` and no work in flight, but the pipeline has NOT drained | No |
| `safety_timeout` | Scan older than `ScanSafetyTimeout` (3h) | No |
| `interrupted_by_restart` | Scan was running when the scanner started (closed as `failed`) | No |

**Degraded assets.** Domain discovery reports a root domain asset whose attack surface it could
not fully see. It publishes one signal message per discovery job (`DiscoveryFinding.Degraded`:
`asset_id`, `domain`, `reason`; no asset) on `domain_discovery_results` before it ACKs the job,
so the pipeline cannot read as drained before ingestion records it. Domain ingestion adds it to
the scan's `degraded_assets` with `$addToSet`. The reasons, in the order discovery picks one:

| `reason` | When |
|----------|------|
| `root_nxdomain` | The local resolver says the root does not exist and the public resolvers confirm NXDOMAIN |
| `dns_failures` | The root lookup failed (timeout, SERVFAIL, refused, network error), or the local resolver says "not found" but a public resolver has an address, or the public check is off or got no answer; or more than 20% of more than 50 subdomain lookups failed |
| `subdomain_enumeration_failed` | subfinder returned an error |

A clean NXDOMAIN from the local resolver is ambiguous: Docker's embedded DNS reports an upstream
REFUSED as NXDOMAIN. So for the root only, discovery asks the resolvers in
`DNS_RECHECK_RESOLVERS` (default `1.1.1.1,8.8.8.8`; `off` disables it) directly over UDP, with TCP
on truncation or loss, for A and AAAA (`recheck.go`). The answer only classifies the root; it is
never used as a scan target. A root that exists without an address (NOERROR, no A or AAAA) is not
degraded: that is a fact about the apex, and its subdomains are still enumerated. A root that
does not exist is not enumerated. Subdomain lookups do not retry a clean NXDOMAIN; only lookup
failures are retried.

At a reconciling close the monitor takes every open finding of the organization whose `scan_ids`
does not contain this scan, and keeps open the ones under a degraded root (`partitionByDegraded`):

- a domain or subdomain discovery whose name is the degraded domain or ends with `.` + domain;
- an IP or port discovery whose `ip` any of those names has ever resolved to
  (`resolution_history`). IP discoveries are shared per organization, so an IP that a healthy
  root also uses stays open too;
- a finding whose discovery is missing or has no name or address.

The mapping is computed at close time from the discoveries, not stamped on findings at ingestion:
the findings at risk are the ones this scan did not ingest. The kept findings are written to the
scan's `unchecked_finding_ids`; the web app shows them as "not checked" in a scan comparison
instead of "resolved". Every other open finding not seen is resolved.

Because the candidates are all open findings not seen (not only those the previous scan saw), a
finding that a partial scan could not check is resolved by the first later scan that checks its
asset. An organization whose every scan has a degraded asset (an expired domain) still resolves
the findings of its other assets.

`findings_reconciled` means the whole scan was reconciled: `true` only for a reconciling close
with no `degraded_assets`. The web app shows every scan with `findings_reconciled: false` as a
"partial scan". `stats.resolved_findings` counts the findings the close resolved (0 when it
resolved none). The `new_*`/`resolved_discoveries` counters still compare with the previous
completed scan; a scan closed by a timeout or restart is no baseline for them, a drained scan
with degraded assets is (`computeStats`).

Only one scan per organization is active at a time; see the lifecycle rules in [DATABASE.md](DATABASE.md#scans-collection).

---

## Knowledge Base Engine Architecture

**Location:** `src/internal/enrichers/knowledge_base/`

The KB engine is **optional**. `nightwatch` starts it only when
`ANTHROPIC_API_KEY` is set; otherwise findings show the scanners' own
`description`, `remediation` and `references`, and `kb_generation_queue` keeps
its jobs until the key is configured.

```
security_findings → findings_ingestion
    ├── Persist to MongoDB
    ├── Check: finding_type not empty?
    ├── Check: Redis SETNX lock (kb_generating:{findingType}, 24h TTL)
    ├── Check: knowledge_base collection has no entry for this finding_type?
    └── If all pass: publish to kb_generation_queue
            └──► knowledge-base-engine
                    ├── Load system prompt + response schema from embedded files
                    ├── Filter attacker-controlled metadata (safeMetadataForKB)
                    ├── Call Anthropic Claude API (temperature 0.3, max_tokens 8192)
                    ├── Parse JSON response (business + technical sections)
                    └── Publish to kb_generation_results
                            └──► kb_ingestion
                                    └── Upsert to knowledge_base collection (_id = "kb_" + findingType)
```

**Key design:** ONE entry per unique finding_type (~84 types), shared across all orgs. Uses `$setOnInsert` for idempotent writes. The web app reads from this collection for recommendations, reports, and security scores.

**Components:** Anthropic client with retry logic (429/502/503/504/529), embedded prompts, bounded response reads (1MB), prompt injection mitigation via metadata filtering.

---

## Discovery Enrichment Architecture

**Location:** `src/internal/active_recon/discovery_enrichment/`

Combines two enrichment types in a single service:

**WAF Detection** (`waf/patterns/`):
- Sends HTTP probes (normal + 10 attack payloads: XSS, SQLi, LFI, etc.)
- Analyzes responses against 68 WAF signature patterns (ported from wafw00f)
- Match requires 2+ checks to pass for confidence
- Detects: Cloudflare, Akamai, AWS WAF, Azure Front Door, Google Cloud Armor, Imperva, ModSecurity, and 60+ others

**IP Geolocation** (`geolocation/`):
- MaxMind MMDB database for IP lookups
- Extracts continent, country, ISP

**Enrichment routing by asset_type:**
- Domain/Subdomain → geolocation + WAF detection
- IP → geolocation only
- Port → skip

---

## Active Recon Scanner Pattern

Active recon scanners follow a consistent architecture. See `js_dependency_scanner` and `http_header_scanner` as reference implementations.

**Standard directory layout:**
```
src/internal/active_recon/[scanner_name]/
├── constants.go      # Consumer group name
├── models.go         # Scanner-specific models (optional)
├── service.go        # Orchestration layer
├── consumer.go       # Redis consumer (single or dual-stream)
└── scanner/          # Pure scanning logic (no Redis/MongoDB)
    └── scanner.go    # Scanner interface + implementation
```

**Key principle:** Separation of concerns — `service.go` orchestrates, `scanner/` does pure scanning (testable, no infrastructure deps).

---

## Ingestion Architecture

**Location:** `src/internal/ingestion/`

The orchestrator runs all consumer slices concurrently:

| Slice | Consumes | Writes To | Also Publishes |
|-------|----------|-----------|----------------|
| domain_ingestion | `domain_discovery_results` | `discoveries` | `ip_discovery_queue`, `discovery_enrichment_queue`, `domain_scan_triggers` |
| port_ingestion | `ip_discovery_results` | `discoveries` | `discovery_enrichment_queue`, `port_scan_triggers` |
| findings_ingestion | `security_findings` | `findings` | `kb_generation_queue` |
| enrichment_ingestion | `discovery_enrichment_results` | `discoveries` | — |
| kb_ingestion | `kb_generation_results` | `knowledge_base` | — |

---

## Key Design Decisions

- **Org-scoped with type discrimination:** Single `discoveries` collection stores all 4 asset types via `asset_type` field
- **Denormalized:** Same physical asset creates separate records per org (no joins, more storage)
- **Two status fields:** `status` (technical: active/inactive/unknown) vs `ownership_status` (org: verified/notMine/notSure)
- **Parent-child hierarchy (org-scoped):** domain → subdomain → IP → port via `parent_id`
- **History tracking:** IP resolution changes (domains), service changes (ports), scan tracking (`scan_ids` array with `$addToSet`)
- **Protocol-aware dedup:** `192.168.1.1:53/tcp` ≠ `192.168.1.1:53/udp`
- **Separation of concerns:** Discovery services publish to Redis, ingestion service persists to MongoDB
- **Single binary:** `nightwatch` initializes config, logger, tracing, Redis and MongoDB once and supervises every component; a failing component stops the process so the container restarts cleanly
