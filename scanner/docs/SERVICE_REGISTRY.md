# Service Registry

> **Single source of truth** for all services, Redis streams, consumer groups, and MongoDB collections.
> Keep this in sync with code changes — the scan_monitor bug class happens when this drifts.

## Service Inventory

| # | Service | Consumer Group | Consumes From | Produces To | Bootstrap | MongoDB |
|---|---------|---------------|---------------|-------------|-----------|---------|
| 1 | **domain-discovery** | `shodan_subdomain_service` | `domain_discovery_queue` | `domain_discovery_results` | RunSimple (Streams) | No |
| 2 | **port-discovery** | `port_discovery_service` | `ip_discovery_queue` | `ip_discovery_results` | RunSimple (Streams) | No |
| 3 | **nuclei-scanner** | `nuclei_scanner_service` | `domain_scan_triggers` + `port_scan_triggers` | `security_findings` | RunSimple (manual) | No |
| 4 | **testssl-scanner** | `testssl_scanner_service` | `domain_scan_triggers` + `port_scan_triggers` | `security_findings` | RunSimple (manual) | No |
| 5 | **webtechprofiler** | `webtechprofiler_service` | `domain_scan_triggers` + `ip_discovery_results` | `security_findings` | RunSimple (manual) | No |
| 6 | **js-dependency-scanner** | `js_dependency_scanner_service` | `domain_scan_triggers` | `security_findings` | Run | No |
| 7 | **http-header-scanner** | `http_header_scanner_service` | `domain_scan_triggers` | `security_findings` | RunSimple (manual) | No |
| 8 | **email-security-scanner** | `email_security_scanner_service` | `domain_scan_triggers` | `security_findings` | RunSimple (manual) | No |
| 9 | **discovery-enrichment** | `discovery_enrichment_service` | `discovery_enrichment_queue` | `discovery_enrichment_results` | RunSimple (manual) | No |
| 10 | **knowledge-base-engine** | `knowledge_base_engine_service` | `kb_generation_queue` | `kb_generation_results` | RunSimple (Streams) | No |
| 11 | **domain-ingestion** | `domain_ingestion_service` | `domain_discovery_results` | `ip_discovery_queue`, `discovery_enrichment_queue`, `domain_scan_triggers` | Orchestrator | Yes |
| 12 | **port-ingestion** | `port_ingestion_service` | `ip_discovery_results` | `discovery_enrichment_queue`, `port_scan_triggers` | Orchestrator | Yes |
| 13 | **findings-ingestion** | `findings_ingestion_service` | `security_findings` | `kb_generation_queue` | Orchestrator | Yes |
| 14 | **enrichment-ingestion** | `enrichment_ingestion_service` | `discovery_enrichment_results` | MongoDB `discoveries` | Orchestrator | Yes |
| 15 | **kb-ingestion** | `kb_ingestion_service` | `kb_generation_results` | MongoDB `knowledge_base` | Orchestrator | Yes |
| 16 | **audit-ingestion** | `audit_ingestion_service` | `system_audit_logs` | MongoDB `audit_logs` | Orchestrator | Yes |
| 17 | **scan-coordinator** | _(scheduler, not consumer)_ | — | `domain_discovery_queue`, `ip_discovery_queue` | Manual | Yes (read) |

**Notes:**
- Ingestion services (#11–16) run as concurrent slices inside a single ingestion orchestrator process
- Scan coordinator (#17) uses cron scheduling, not consumer groups

---

## Redis Streams

| Stream | Constant | Category | Producers | Consumers | Start Pos |
|--------|----------|----------|-----------|-----------|-----------|
| `domain_discovery_queue` | `StreamDomainDiscoveryQueue` | job | scan-coordinator | domain-discovery | `0` |
| `domain_discovery_results` | `StreamDomainDiscoveryResults` | result | domain-discovery | domain-ingestion | `0` |
| `ip_discovery_queue` | `StreamIPDiscoveryQueue` | job | scan-coordinator, domain-ingestion | port-discovery | `0` |
| `ip_discovery_results` | `StreamIPDiscoveryResults` | result | port-discovery | port-ingestion, webtechprofiler | `0` |
| `domain_scan_triggers` | `StreamDomainScanTriggers` | trigger | domain-ingestion | nuclei, testssl, webtechprofiler, js-dep, http-header, email-security | `$` |
| `port_scan_triggers` | `StreamPortScanTriggers` | trigger | port-ingestion | nuclei, testssl | `$` |
| `security_findings` | `StreamSecurityFindings` | result | nuclei, testssl, webtechprofiler, js-dep, http-header, email-security | findings-ingestion | `0` |
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

**Source:** `src/internal/scan_coordinator/scan_monitor.go:105-131` — `isComplete()`

The scan monitor tracks these consumer groups to determine when a scan is complete. A scan is marked "done" when ALL of these have 0 pending messages for the scan_id:

| Stream | Consumer Group | Service |
|--------|---------------|---------|
| `domain_scan_triggers` | `nuclei_scanner_service` | nuclei-scanner |
| `domain_scan_triggers` | `testssl_scanner_service` | testssl-scanner |
| `domain_scan_triggers` | `webtechprofiler_service` | webtechprofiler |
| `domain_scan_triggers` | `js_dependency_scanner_service` | js-dependency-scanner |
| `domain_scan_triggers` | `http_header_scanner_service` | http-header-scanner |
| `domain_scan_triggers` | `email_security_scanner_service` | email-security-scanner |
| `port_scan_triggers` | `nuclei_scanner_service` | nuclei-scanner |
| `port_scan_triggers` | `testssl_scanner_service` | testssl-scanner |
| `domain_discovery_results` | `domain_ingestion_service` | domain-ingestion |
| `ip_discovery_results` | `port_ingestion_service` | port-ingestion |
| `ip_discovery_results` | `webtechprofiler_service` | webtechprofiler |
| `security_findings` | `findings_ingestion_service` | findings-ingestion |

**When adding a new active recon scanner:** You MUST add its consumer group to this list or scans will complete before the new scanner finishes processing.

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
- **webtechprofiler**: `$` on `domain_scan_triggers` (ephemeral) + `0` on `ip_discovery_results` (guaranteed)
- **nuclei-scanner**: `$` on both `domain_scan_triggers` and `port_scan_triggers`
- **testssl-scanner**: `$` on both `domain_scan_triggers` and `port_scan_triggers`

---

## MongoDB Collections

| Collection | Constant | Purpose | Writer(s) |
|------------|----------|---------|-----------|
| `assets` | `CollectionAssets` | User-added assets to scan (managed via UI) | Dashboard |
| `discoveries` | `CollectionDiscoveries` | Org-scoped scan results (domain, subdomain, ip, port) | domain-ingestion, port-ingestion, enrichment-ingestion |
| `findings` | `CollectionFindings` | Security vulnerabilities from scanners | findings-ingestion |
| `knowledge_base` | `CollectionKnowledgeBase` | Shared KB entries keyed by finding_type (~84 entries) | kb-ingestion |
| `organizations` | `CollectionOrganizations` | Org settings with subscription/scan config | Dashboard |
| `scans` | `CollectionScans` | Scan execution records | scan-coordinator, scan-monitor |
| `audit_logs` | `CollectionAuditLogs` | System audit events | audit-ingestion |

**Read-only access (NightWatch):** `assets`, `organizations` — written by Dashboard, read by scan-coordinator.

---

## Consumer Group Constants Location

Each service defines its consumer group constant in its own `constants.go`:

| Service | File | Constant |
|---------|------|----------|
| domain-discovery | `src/internal/discoveries/domain_discovery/constants.go` | `GroupShodanSubdomainService` |
| port-discovery | `src/internal/discoveries/port_discovery/constants.go` | `GroupPortDiscovery` |
| nuclei-scanner | `src/internal/active_recon/nuclei_scanner/constants.go` | `GroupNucleiScanner` |
| testssl-scanner | `src/internal/active_recon/testssl_scanner/constants.go` | `GroupTestSSLScanner` |
| webtechprofiler | `src/internal/active_recon/webtechprofiler/constants.go` | `GroupWebTechProfiler` |
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
