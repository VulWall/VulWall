# Service Registry

> **Single source of truth** for all components, Redis streams, consumer groups, and MongoDB collections.
> Keep this in sync with code changes — the scan_monitor bug class happens when this drifts.

## Component Inventory

All components run as goroutines inside **one process**, the `nightwatch` binary
(`src/cmd/nightwatch/main.go`). They share one Redis client, one MongoDB client,
one logger and one tracer provider, and they still talk to each other only
through Redis streams. If one component returns an error, `nightwatch` stops
all of them and exits non-zero, so the container restart policy restarts the
whole scanner.

| # | Component | Consumer Group | Consumes From | Produces To | Started in `main.go` by | MongoDB |
|---|---------|---------------|---------------|-------------|-----------|---------|
| 1 | **domain-discovery** | `domain_discovery_service` | `domain_discovery_queue` | `domain_discovery_results` | `consumers()` | No |
| 2 | **port-discovery** | `port_discovery_service` | `ip_discovery_queue` | `ip_discovery_results` | `consumers()` | No |
| 3 | **nuclei-scanner** | `nuclei_scanner_service` | `domain_scan_triggers` + `port_scan_triggers` | `security_findings` | `consumers()` | No |
| 4 | **testssl-scanner** | `testssl_scanner_service` | `domain_scan_triggers` | `security_findings` | `consumers()` | No |
| 5 | **js-dependency-scanner** | `js_dependency_scanner_service` | `domain_scan_triggers` | `security_findings` | `consumers()` | No |
| 6 | **http-header-scanner** | `http_header_scanner_service` | `domain_scan_triggers` | `security_findings` | `consumers()` | No |
| 7 | **email-security-scanner** | `email_security_scanner_service` | `domain_scan_triggers` | `security_findings` | `consumers()` | No |
| 8 | **discovery-enrichment** | `discovery_enrichment_service` | `discovery_enrichment_queue` | `discovery_enrichment_results` | `consumers()` | No |
| 9 | **knowledge-base-engine** | `knowledge_base_engine_service` | `kb_generation_queue` | `kb_generation_results` | `knowledgeBase()` — only when `ANTHROPIC_API_KEY` is set | No |
| 10 | **domain-ingestion** | `domain_ingestion_service` | `domain_discovery_results` | `ip_discovery_queue`, `discovery_enrichment_queue`, `domain_scan_triggers` | `consumers()` → ingestion orchestrator | Yes |
| 11 | **port-ingestion** | `port_ingestion_service` | `ip_discovery_results` | `discovery_enrichment_queue`, `port_scan_triggers` | `consumers()` → ingestion orchestrator | Yes |
| 12 | **findings-ingestion** | `findings_ingestion_service` | `security_findings` | `kb_generation_queue` | `consumers()` → ingestion orchestrator | Yes |
| 13 | **enrichment-ingestion** | `enrichment_ingestion_service` | `discovery_enrichment_results` | MongoDB `discoveries` | `consumers()` → ingestion orchestrator | Yes |
| 14 | **kb-ingestion** | `kb_ingestion_service` | `kb_generation_results` | MongoDB `knowledge_base` | `consumers()` → ingestion orchestrator | Yes |
| 15 | **audit-ingestion** | `audit_ingestion_service` | `system_audit_logs` | MongoDB `audit_logs` | `consumers()` → ingestion orchestrator | Yes |
| 16 | **scan-coordinator** | _(not a consumer)_ | MongoDB `scans` (status `queued`) | `domain_discovery_queue`, `ip_discovery_queue` | `coordinatorComponents()` | Yes (`scans` only) |

**Notes:**
- Ingestion slices (#10–15) run inside the ingestion orchestrator (`src/internal/ingestion/orchestrator.go`).
- The scan coordinator (#16) is three goroutines: the cron **scheduler** (per-org `scan_cron`, plus stream cleanup), the **queued-scan poller** (every 5 s, claims scans the web app queued), and the **scan monitor** (marks scans `done`). It writes only the `scans` collection; see the scan lifecycle in [DATABASE.md](DATABASE.md#scans-collection).
- Without `ANTHROPIC_API_KEY` the KB engine (#9) does not start. `kb_generation_queue` keeps its jobs until the key is set.
- `main.go` creates the job-queue groups (`0`) and every trigger-stream group (`$`) before any component starts.

---

## Redis Streams

| Stream | Constant | Category | Producers | Consumers | Start Pos |
|--------|----------|----------|-----------|-----------|-----------|
| `domain_discovery_queue` | `StreamDomainDiscoveryQueue` | job | scan-coordinator | domain-discovery | `0` |
| `domain_discovery_results` | `StreamDomainDiscoveryResults` | result | domain-discovery | domain-ingestion | `0` |
| `ip_discovery_queue` | `StreamIPDiscoveryQueue` | job | scan-coordinator, domain-ingestion | port-discovery | `0` |
| `ip_discovery_results` | `StreamIPDiscoveryResults` | result | port-discovery | port-ingestion | `0` |
| `domain_scan_triggers` | `StreamDomainScanTriggers` | trigger | domain-ingestion | nuclei, testssl, js-dep, http-header, email-security | `$` |
| `port_scan_triggers` | `StreamPortScanTriggers` | trigger | port-ingestion | nuclei | `$` |
| `security_findings` | `StreamSecurityFindings` | result | nuclei, testssl, js-dep, http-header, email-security | findings-ingestion | `0` |
| `discovery_enrichment_queue` | `StreamDiscoveryEnrichmentQueue` | job | domain-ingestion, port-ingestion | discovery-enrichment | `0` |
| `discovery_enrichment_results` | `StreamDiscoveryEnrichmentResults` | result | discovery-enrichment | enrichment-ingestion | `0` |
| `kb_generation_queue` | `StreamKBGenerationQueue` | job | findings-ingestion | knowledge-base-engine | `0` |
| `kb_generation_results` | `StreamKBGenerationResults` | result | knowledge-base-engine | kb-ingestion | `0` |
| `system_audit_logs` | `StreamSystemAuditLogs` | audit | various | audit-ingestion | `0` |

**Start Position Key:**
- `0` = CreateConsumerGroup (from beginning) — guaranteed delivery for results, jobs, audits
- `$` = CreateConsumerGroupFromLatest — ephemeral triggers, only process new messages

---

## Scan Monitor Coverage

**Source:** `src/internal/scan_coordinator/pipeline.go` — `scanPipelineGroups()` (consumed by `pipelineQuiescent()` in `scan_monitor.go`)

The scan monitor tracks these consumer groups to determine when a scan is complete. A scan is completed via the **pipeline-quiescence** path when it has run past `ScanMinRuntime`, ingestion has been quiet for `ScanSettleGrace`, and EVERY group below has drained the stream — meaning **0 pending (read-but-unacked) messages AND no undelivered entries** (the group's last-delivered id has reached the stream's last-generated id). The undelivered-entries check is what catches trigger messages still sitting unread on a stream while a single-threaded scanner (nuclei) works through its backlog; an `XPending`-only check was blind to those and marked scans "done" ~30s in. Backstops: `idle_timeout` (no ingestion activity for `ScanIdleTimeout` after `ScanMinRuntime`, and no group below holds work in flight) and `safety_timeout` (3h absolute; skips finding resolution).

**Work in flight** means a group below has a pending entry delivered less than `ScanStuckThreshold` (30 min) ago (`XPENDING` idle of its youngest entry): a live consumer is still working on it, so the idle timeout waits. When every pending entry is older than the threshold, the work is treated as stuck and the idle timeout may close the scan. `SCAN_IDLE_TIMEOUT` and `SCAN_MIN_RUNTIME` (Go durations) override the defaults (15m, 10m); the monitor logs the effective values at startup and logs `Idle timeout suppressed: work in flight` each time the guard holds a scan open.

The table is in check order: upstream stages first. Every stage publishes its results before it ACKs its input (`redisx.ConsumeStream` ACKs after the handler returns, and no handler publishes from a goroutine that outlives it), so reading upstream groups first means a stage that finishes between two reads cannot make the pipeline look drained.

| Stream | Consumer Group | Service |
|--------|---------------|---------|
| `domain_discovery_queue` | `domain_discovery_service` | domain-discovery |
| `domain_discovery_results` | `domain_ingestion_service` | domain-ingestion |
| `ip_discovery_queue` | `port_discovery_service` | port-discovery |
| `ip_discovery_results` | `port_ingestion_service` | port-ingestion |
| `domain_scan_triggers` | `nuclei_scanner_service` | nuclei-scanner |
| `domain_scan_triggers` | `testssl_scanner_service` | testssl-scanner |
| `domain_scan_triggers` | `js_dependency_scanner_service` | js-dependency-scanner |
| `domain_scan_triggers` | `http_header_scanner_service` | http-header-scanner |
| `domain_scan_triggers` | `email_security_scanner_service` | email-security-scanner |
| `port_scan_triggers` | `nuclei_scanner_service` | nuclei-scanner |
| `security_findings` | `findings_ingestion_service` | findings-ingestion |

The two discovery job queues are included because a discovery job can run for many minutes (subfinder plus DNS resolution of thousands of names) while every downstream group is idle; without them a scan was marked `done` mid-discovery and late subdomains arrived after finding resolution.

**When adding a new active recon scanner:** You MUST add its consumer group to `scanPipelineGroups()` in `pipeline.go`, after the stages that feed it (guarded by `TestScanPipelineGroups`) or scans will complete before the new scanner finishes processing.

**Deliberately excluded (only these):** the `discovery_enrichment_*` and `kb_generation_*` streams are terminal branches (enrichment writes only discovery metadata; KB writes only the `knowledge_base` collection) and produce no findings or triggers. They must NOT be added here — gating completion on the slow, cross-org, Anthropic-backed KB queue would let one org's backlog stall every other org's scans.

---

## Stream Cleanup Coverage

**Source:** `src/internal/scan_coordinator/stream_cleanup.go:30-38` — `streamsToClean()`

These 5 result/finding streams are trimmed on a cron schedule (`5 */6 * * *` = every 6 hours):

| Stream | Constant |
|--------|----------|
| `domain_discovery_results` | `StreamDomainDiscoveryResults` |
| `ip_discovery_results` | `StreamIPDiscoveryResults` |
| `security_findings` | `StreamSecurityFindings` |
| `discovery_enrichment_results` | `StreamDiscoveryEnrichmentResults` |
| `kb_generation_results` | `StreamKBGenerationResults` |

**NOT cleaned (by design):**
- Trigger streams (`domain_scan_triggers`, `port_scan_triggers`) — use MAXLEN at publish time
- Job queues (`domain_discovery_queue`, `ip_discovery_queue`, etc.) — managed by consumers

**When adding a new result stream:** Add it to `streamsToClean()` or it will grow unbounded.

---

## Consumer Group Strategy

| Pattern | Start Position | Use When | Examples |
|---------|---------------|----------|----------|
| `CreateConsumerGroup` | `0` (beginning) | Results and jobs that need guaranteed delivery | All ingestion, discovery, enrichment services |
| `CreateConsumerGroupFromLatest` | `$` (latest) | Ephemeral triggers — only process new messages | Active recon scanners on trigger streams |

**Dual-strategy consumers:**
- **nuclei-scanner**: `$` on both `domain_scan_triggers` and `port_scan_triggers`
- **testssl-scanner**: `$` on `domain_scan_triggers` only

---

## MongoDB Collections

| Collection | Constant | Purpose | Writer(s) |
|------------|----------|---------|-----------|
| `assets` | `CollectionAssets` | User-added assets to scan (managed via UI) | web app |
| `discoveries` | `CollectionDiscoveries` | Org-scoped scan results (domain, subdomain, ip, port) | domain-ingestion, port-ingestion, enrichment-ingestion |
| `findings` | `CollectionFindings` | Security vulnerabilities from scanners | findings-ingestion |
| `knowledge_base` | `CollectionKnowledgeBase` | Shared KB entries keyed by finding_type (~84 entries) | kb-ingestion |
| `organizations` | `CollectionOrganizations` | Org settings with subscription/scan config | web app |
| `scans` | `CollectionScans` | Scan execution records | web app (inserts `queued`), scan-coordinator, scan-monitor |
| `audit_logs` | `CollectionAuditLogs` | System audit events | audit-ingestion |

**Read-only access (scanner):** `assets`, `organizations` — written by the web app, read by scan-coordinator. The web app creates the default organization with `subscription_settings.scan_cron`.

---

## Consumer Group Constants Location

Each service defines its consumer group constant in its own `constants.go`:

| Service | File | Constant |
|---------|------|----------|
| domain-discovery | `src/internal/discoveries/domain_discovery/constants.go` | `GroupDomainDiscovery` |
| port-discovery | `src/internal/discoveries/port_discovery/constants.go` | `GroupPortDiscovery` |
| nuclei-scanner | `src/internal/active_recon/nuclei_scanner/constants.go` | `GroupNucleiScanner` |
| testssl-scanner | `src/internal/active_recon/testssl_scanner/constants.go` | `GroupTestSSLScanner` |
| js-dependency-scanner | `src/internal/active_recon/js_dependency_scanner/constants.go` | `GroupJSDependencyScanner` |
| http-header-scanner | `src/internal/active_recon/http_header_scanner/constants.go` | `GroupHTTPHeaderScanner` |
| email-security-scanner | `src/internal/active_recon/email_security_scanner/constants.go` | `GroupEmailSecurityScanner` |
| discovery-enrichment | `src/internal/active_recon/discovery_enrichment/constants.go` | `GroupDiscoveryEnrichment` |
| knowledge-base-engine | `src/internal/enrichers/knowledge_base/constants.go` | `GroupKBEngine` |
| domain-ingestion | `src/internal/ingestion/domain_ingestion/constants.go` | `GroupDomainIngestion` |
| port-ingestion | `src/internal/ingestion/port_ingestion/constants.go` | `GroupPortIngestion` |
| findings-ingestion | `src/internal/ingestion/findings_ingestion/constants.go` | `GroupFindingsIngestion` |
| enrichment-ingestion | `src/internal/ingestion/enrichment_ingestion/constants.go` | `GroupEnrichmentIngestion` |
| kb-ingestion | `src/internal/ingestion/kb_ingestion/constants.go` | `GroupKBIngestion` |
| audit-ingestion | `src/internal/ingestion/audit_ingestion/constants.go` | `GroupAuditIngestion` |

Shared stream/collection constants live in `src/internal/shared/constants.go`.
