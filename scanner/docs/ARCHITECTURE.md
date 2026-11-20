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
5. Scan monitor marks the scan done when every pipeline group has drained (`scanPipelineGroups()` in `pipeline.go`)
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

**Scan completion and finding resolution.** Closing a scan as `done` can also resolve findings.
A false resolution tells a customer that an unfixed vulnerability is fixed, so a scan resolves a
finding only on **positive evidence** that it is gone, never because data is missing
(`reconcileFindings()` in `scan_monitor.go`, `decideResolutions()` in `finding_resolution.go`).
Each close writes `completion_reason` and `findings_reconciled` on the scan (a queued scan with
no enabled assets is closed `done` at once with only `findings_reconciled: false`):

| `completion_reason` | When | Resolves findings |
|---------------------|------|-------------------|
| `pipeline_quiescent` | Past `ScanMinRuntime`, ingestion quiet for `ScanSettleGrace`, every scan-pipeline group drained | Yes, the ones with positive evidence (below) |
| `idle_timeout` | No ingestion activity for `ScanIdleTimeout` and no work in flight, but the pipeline has NOT drained | No |
| `safety_timeout` | Scan older than `ScanSafetyTimeout` (3h) | No |
| `interrupted_by_restart` | Scan was running when the scanner started (closed as `failed`) | No |

**Coverage: the evidence.** Every check reports what it covered in a `ScanCoverage` message
(`shared/coverage.go`), published on `security_findings` after its results and before it ACKs
its input, so the scan cannot drain before the evidence lands. `findings_ingestion` stores it in
`scan_coverage`, one record per `(scan_id, source, discovery_id)` ([DATABASE.md](DATABASE.md#scan_coverage-collection)):

| Source | `status` | Means |
|--------|----------|-------|
| a scanner (`nuclei`, `testssl`, `jsscanner`, `http-headers`, `email-security`) | `ok` + `reported` | The check ran to completion on that discovery; `reported` lists the `(finding_type, title)` of every finding it reported |
| a scanner | `error` | The check did not complete: a tool error; a testssl.sh run that exited non-zero (1-239: checks that could not run; 240+: fatal) or whose JSON has no numeric `scanTime` or has a `scanProblem`/`FATAL` entry; a nuclei or testssl target that no longer accepts a TCP connection after the run (`shared.Reachable`: nuclei reports "no findings" also for a target that went down or banned the scanner mid-run); a nuclei run that exited non-zero, logged `[FTL]` or no "Scan completed", or dropped the target (`Skipped <host:port> from target list`, which nuclei logs and still exits 0); a nuclei target whose root answers 403, 429, 5xx or a WAF challenge after the run; an http/https probe that neither answered nor refused (timeout, TLS failure, 403/429/5xx, a WAF challenge: `shared.BlockedResponse`; a 404 or 410 is a definite answer, `shared.ErrGone`); an http/https check in which both protocols refused the connection (`shared.ErrNoAnswer`: nothing was checked); a JS file that did not download (other than 404/410) or came back as a WAF challenge page; a retire.js failure; a transient SPF/DMARC/NS/MX lookup error; an AXFR attempt that timed out before any record, or a nameserver that did not resolve (one the SSRF guard refuses is skipped); a "no record" answer (SPF, DMARC, MX, NS) that the public resolvers did not confirm; a 403, 429 or 5xx answer, a WAF challenge, or a failed CORS or HTTPS-redirect request in the header check; or a host that did not resolve in this scan |
| `domain_discovery` | `absent` | A domain or subdomain that an earlier scan saw has no address: the local resolver and every public resolver (`DNS_RECHECK_RESOLVERS`) say NXDOMAIN or NODATA |
| `port_discovery` | `ok` | The port scan of that IP completed and found at least one port open (discovery id = the IP's). A scan with no open port is no evidence: a block looks the same |

A scanner that cannot publish a finding returns the error instead of reporting `ok`, so the
trigger is retried (`redisx.ConsumeStream`, 3 attempts, then the `dead_letter` stream); a dead
trigger leaves no `ok`. Duplicate runs in one scan merge so that `error` sticks and `reported` is
the union.

**The rule.** At a `pipeline_quiescent` close the candidates are every open finding of the
organization whose `scan_ids` does not contain this scan (so a finding one scan could not check
is resolved by the first later scan that has the evidence). A candidate is resolved when:

- `not_reproduced`: its discovery has this scan in `scan_ids` (re-discovered live), the
  `scan_coverage` record of this scan for `(finding.source, finding.discovery_id)` is `ok`, and
  its `(finding_type, title)` is not in `reported`. Because the key list travels with the
  coverage, a finding message that ingestion lost cannot be mistaken for a fixed one.
- `host_no_longer_found`: its host was confirmed gone in each of the last 3 scans that closed
  `pipeline_quiescent`, this one included: a domain or subdomain with a `domain_discovery`
  `absent` record in each, or a port whose IP has a `port_discovery` `ok` record in each while
  the port was not open (not in `scan_ids`) in any. IP discoveries are never gone this way, and
  neither are the ports of an IP that no name resolves to any more (it gets no port scan): their
  findings stay open.

Everything else stays open: a missing or `error` coverage record, a host not seen this scan
(a subdomain lost to NXDOMAIN or subfinder variance, a filtered port), a disabled asset (not
scanned), a scanner that crashed. Resolved findings get `resolution_reason`,
`resolved_by_scan_id` and `resolved_at`; a finding reported again is reopened and loses them.
The open candidates are counted in `stats.unchecked_findings` and listed in
`unchecked_finding_ids`; the web app shows them as "not checked" in a scan comparison.

**Known subdomains.** The coordinator gives each domain discovery job the names below the domain
that a scan saw in the last 90 days (`known_subdomains`, read from `discoveries`). Discovery
resolves them together with subfinder's names, also when subfinder fails, so a live host is not
lost to passive-source variance. A known name that the local resolver reports as not found is
asked again of the public resolvers: an address there is published (the local resolver failed),
"no address" from all of them is reported `absent`. Names that subfinder returns for the first
time do not retry a clean NXDOMAIN (passive sources return many stale names); only lookup
failures are retried.

**Degraded assets (information only).** Domain discovery reports a root domain asset whose
attack surface it could not fully see. It publishes one signal message per discovery job
(`DiscoveryFinding.Degraded`: `asset_id`, `domain`, `reason`; no asset) on
`domain_discovery_results` before it ACKs the job; domain ingestion adds it to the scan's
`degraded_assets` with `$addToSet`. Finding resolution does not depend on it. The reasons, in
the order discovery picks one:

| `reason` | When |
|----------|------|
| `root_nxdomain` | The local resolver says the root does not exist and the public resolvers confirm NXDOMAIN (also reported `absent`) |
| `dns_failures` | The root lookup failed (timeout, SERVFAIL, refused, network error), or the local resolver says "not found" but a public resolver has an address, or the public check is off or got no answer; or any known subdomain's lookup failed; or more than 20% of more than 10 subdomain lookups failed |
| `publish_failed` | Some subdomain or absence messages failed to publish (the job is then retried) |
| `subdomain_enumeration_failed` | subfinder returned an error (the known names are still checked) |

A clean NXDOMAIN from the local resolver is ambiguous: Docker's embedded DNS reports an upstream
REFUSED as NXDOMAIN. So for the root and the known subdomains, discovery asks the resolvers in
`DNS_RECHECK_RESOLVERS` (default `1.1.1.1,8.8.8.8`; `off` disables it) directly over UDP, with
TCP on truncation or loss, for A and AAAA (`recheck.go`). A root that exists without an address
(NOERROR, no A or AAAA) is not degraded: that is a fact about the apex, and its subdomains are
still enumerated. A root that does not exist is not enumerated; its known names are still checked.

`findings_reconciled` is `true` for a `pipeline_quiescent` close with no `degraded_assets`. The
web app shows every scan with `findings_reconciled: false` as a "partial scan" and names its
`stats.unchecked_findings`. `stats.resolved_findings` counts the findings the close resolved.
The `new_*`/`resolved_discoveries` counters still compare with the previous scan that closed
`pipeline_quiescent` (`computeStats`).

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
- DB-IP Lite country and ASN databases (MMDB format), downloaded when the container starts
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

**Coverage contract:** after a target, `service.go` publishes its findings, then
`shared.TargetCoverage(source, target, reported, err)` with the keys it reported, or with the
error that kept the check from completing. A tool failure is a coverage `error` and the handler
returns nil (no retry of a slow scan); only a failed publish is returned as a handler error. Be
strict about "complete": a check that hid an error behind "no findings" resolves real findings.

---

## Ingestion Architecture

**Location:** `src/internal/ingestion/`

The orchestrator runs all consumer slices concurrently:

| Slice | Consumes | Writes To | Also Publishes |
|-------|----------|-----------|----------------|
| domain_ingestion | `domain_discovery_results` | `discoveries` | `ip_discovery_queue`, `discovery_enrichment_queue`, `domain_scan_triggers` |
| port_ingestion | `ip_discovery_results` | `discoveries` | `discovery_enrichment_queue`, `port_scan_triggers` |
| findings_ingestion | `security_findings` | `findings`, `scan_coverage` | `kb_generation_queue` |
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
