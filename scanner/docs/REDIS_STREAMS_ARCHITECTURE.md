# Redis Streams Architecture

## Overview

This document visualizes all Redis streams in the VulWall NightWatch system, showing publishers and consumers for each stream.

---

## Stream 1: `domain_discovery_queue`

**Purpose:** Input queue for domain discovery jobs

**Publishers:**
- 🔵 **scan-coordinator** - Publishes jobs for active user assets (scheduled scans)
  - File: `internal/scan_coordinator/service.go`
  - Consumer Group: N/A (publisher only)

**Consumers:**
- 🟢 **domain-discovery** (Shodan)
  - File: `internal/discoveries/domain_discovery/consumer.go`
  - Consumer Group: `shodan_subdomain_service`
  - Action: Performs subdomain enumeration and IP resolution

```
┌──────────────────────────────────────────────────────────────┐
│                  domain_discovery_queue                       │
└──────────────────────────────────────────────────────────────┘
                              ▲
                              │ publishes
                              │
                    ┌─────────────────────┐
                    │  scan-coordinator   │
                    │   (scheduler)       │
                    └─────────────────────┘
                              │
                              ▼ consumes
                              │
                    ┌─────────────────────┐
                    │  domain-discovery   │
                    │     (Shodan)        │
                    └─────────────────────┘
```

---

## Stream 2: `domain_discovery_results`

**Purpose:** Discovery findings from domain enumeration (domains, subdomains, IPs)

**Publishers:**
- 🟢 **domain-discovery** (Shodan)
  - File: `internal/discoveries/domain_discovery/service.go`
  - Consumer Group: N/A (publisher only)
  - Publishes: `DiscoveryFinding` (source="shodan")

**Consumers:**
- 🟠 **ingestion** (domain_ingestion slice) **ONLY**
  - File: `internal/ingestion/domain_ingestion/consumer.go`
  - Consumer Group: `domain_ingestion_service`
  - Action: Persists domains/subdomains/IPs to MongoDB `discoveries` collection, then publishes to `domain_scan_triggers`

```
                    ┌─────────────────────┐
                    │  domain-discovery   │
                    │     (Shodan)        │
                    └─────────────────────┘
                              │ publishes
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                domain_discovery_results                       │
│  (domains, subdomains, IPs with source="shodan")             │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumed by INGESTION ONLY
                              ▼
                    ┌─────────────────────┐
                    │     ingestion       │
                    │  (domain slice)     │
                    └─────────────────────┘
                              │
                              ▼
                      MongoDB discoveries
                              │
                              └─► Publishes to:
                                    - ip_discovery_queue (for port scanning)
                                    - discovery_enrichment_queue (for WAF/geo)
                                    - domain_scan_triggers (for active recon)
```

---

## Stream 3: `ip_discovery_queue`

**Purpose:** Input queue for IP port scanning jobs

**Publishers:**
- 🟠 **ingestion** (domain_ingestion slice)
  - File: `internal/ingestion/domain_ingestion/service.go`
  - Publishes: `IPDiscoveryJob` (triggered when new IPs are discovered)

- 🔵 **scan-coordinator**
  - File: `internal/scan_coordinator/service.go`
  - Publishes: `IPDiscoveryJob` (for user-added IP assets during scheduled scans)

**Consumers:**
- 🟢 **port-discovery**
  - File: `internal/discoveries/port_discovery/consumer.go`
  - Consumer Group: `port_discovery_service`
  - Action: Scans 23 common TCP ports

```
┌─────────────────┐          ┌─────────────────┐
│   ingestion     │          │ scan-coordinator│
│ (domain slice)  │          │   (scheduler)   │
└─────────────────┘          └─────────────────┘
         │ publishes                  │ publishes
         │ (new IPs)                  │ (user IP assets)
         ▼                            ▼
┌──────────────────────────────────────────────────────────────┐
│                    ip_discovery_queue                         │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumes
                              ▼
                    ┌─────────────────────┐
                    │   port-discovery    │
                    │   (TCP scanner)     │
                    └─────────────────────┘
```

---

## Stream 4: `ip_discovery_results`

**Purpose:** Port discovery findings (open ports with service info)

**Publishers:**
- 🟢 **port-discovery**
  - File: `internal/discoveries/port_discovery/service.go`
  - Publishes: `IPDiscoveryFinding` (source="port_discovery")

**Consumers:**
- 🟠 **ingestion** (port_ingestion slice) **ONLY**
  - File: `internal/ingestion/port_ingestion/consumer.go`
  - Consumer Group: `port_ingestion_service`
  - Action: Persists ports to MongoDB `discoveries` collection, then publishes to `port_scan_triggers`

```
                    ┌─────────────────────┐
                    │   port-discovery    │
                    │   (TCP scanner)     │
                    └─────────────────────┘
                              │ publishes
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                  ip_discovery_results                         │
│      (ports with service info, source="port_discovery")       │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumed by INGESTION ONLY
                              ▼
                    ┌─────────────────────┐
                    │     ingestion       │
                    │   (port slice)      │
                    └─────────────────────┘
                              │
                              ▼
                      MongoDB discoveries
                              │
                              └─► Publishes to port_scan_triggers (for active recon)
```

---

## Stream 5: `security_findings`

**Purpose:** Security vulnerabilities discovered by active recon scanners

**Publishers:**
- 🟣 **nuclei-scanner**
  - File: `internal/active_recon/nuclei_scanner/service.go`
  - Publishes: `SecurityFinding` (source="nuclei")

- 🟣 **nikto-scanner**
  - File: `internal/active_recon/nikto_scanner/service.go`
  - Publishes: `SecurityFinding` (source="nikto")

- 🟣 **testssl-scanner**
  - File: `internal/active_recon/testssl_scanner/service.go`
  - Publishes: `SecurityFinding` (source="testssl")

- 🟣 **webtechprofiler**
  - File: `internal/active_recon/webtechprofiler/service.go`
  - Publishes: `SecurityFinding` (source="webtechprofiler")

- 🟣 **js-dependency-scanner**
  - File: `internal/active_recon/js_dependency_scanner/service.go`
  - Publishes: `SecurityFinding` (source="jsscanner")

**Consumers:**
- 🟠 **ingestion** (findings_ingestion slice)
  - File: `internal/ingestion/findings_ingestion/consumer.go`
  - Consumer Group: `findings_ingestion_service`
  - Action: Persists findings to MongoDB `findings` collection

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  nuclei-scanner │  │  nikto-scanner  │  │ testssl-scanner │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
┌─────────────────┐  ┌─────────────────┐
│ webtechprofiler │  │  js-dependency  │
│                 │  │    scanner      │
└─────────────────┘  └─────────────────┘
         │                    │
         └────────────────────┘
                              │ publishes
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                     security_findings                         │
│  (vulnerabilities from all scanners with source field)        │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumes
                              ▼
                    ┌─────────────────────┐
                    │     ingestion       │
                    │  (findings slice)   │
                    └─────────────────────┘
                              │
                              ▼
                      MongoDB findings
```

---

## Stream 6: `discovery_enrichment_queue`

**Purpose:** Jobs for enriching discoveries with WAF detection and IP geolocation

**Publishers:**
- 🟠 **ingestion** (domain_ingestion slice)
  - File: `internal/ingestion/domain_ingestion/service.go`
  - Publishes: `EnrichmentJob` (after persisting discoveries)

**Consumers:**
- 🟣 **discovery-enrichment**
  - File: `internal/active_recon/discovery_enrichment/consumer.go`
  - Consumer Group: `discovery_enrichment_service`
  - Action: Performs WAF detection and IP geolocation

```
┌─────────────────┐
│   ingestion     │
│ (domain slice)  │
└─────────────────┘
         │ publishes (after persisting)
         ▼
┌──────────────────────────────────────────────────────────────┐
│              discovery_enrichment_queue                       │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumes
                              ▼
                    ┌─────────────────────┐
                    │ discovery-enrichment│
                    │ (WAF + Geolocation) │
                    └─────────────────────┘
```

---

## Stream 7: `discovery_enrichment_results`

**Purpose:** Enrichment findings (WAF detection, IP geolocation)

**Publishers:**
- 🟣 **discovery-enrichment**
  - File: `internal/active_recon/discovery_enrichment/service.go`
  - Publishes: `EnrichmentFinding` (enrichment_type="waf" or "geolocation")

**Consumers:**
- 🟠 **ingestion** (enrichment_ingestion slice)
  - File: `internal/ingestion/enrichment_ingestion/consumer.go`
  - Consumer Group: `enrichment_ingestion_service`
  - Action: Updates discoveries in MongoDB with enrichment metadata

```
                    ┌─────────────────────┐
                    │ discovery-enrichment│
                    │ (WAF + Geolocation) │
                    └─────────────────────┘
                              │ publishes
                              ▼
┌──────────────────────────────────────────────────────────────┐
│            discovery_enrichment_results                       │
│      (WAF + geolocation data with enrichment_type field)      │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumes
                              ▼
                    ┌─────────────────────┐
                    │     ingestion       │
                    │ (enrichment slice)  │
                    └─────────────────────┘
                              │
                              ▼
                MongoDB discoveries (updates metadata)
```

---

## Stream 8: `domain_scan_triggers`

**Purpose:** Triggers active recon scanners on domains/subdomains (published AFTER ingestion)

**Publishers:**
- 🟠 **ingestion** (domain_ingestion slice)
  - File: `internal/ingestion/domain_ingestion/service.go`
  - Publishes: `DiscoveryFinding` (with trace context from ingest_domain_finding span)

**Consumers:**
- 🟣 **js-dependency-scanner**
  - File: `internal/active_recon/js_dependency_scanner/consumer.go`
  - Consumer Group: `js_dependency_scanner_service`
  - Action: Scans JavaScript dependencies for vulnerabilities (retire.js)

- 🟣 **webtechprofiler**
  - File: `internal/active_recon/webtechprofiler/consumer.go`
  - Consumer Group: `webtechprofiler_service`
  - Action: Profiles web technologies (Wappalyzer)

- 🟣 **nuclei-scanner**
  - File: `internal/active_recon/nuclei_scanner/consumer.go`
  - Consumer Group: `nuclei_scanner_service`
  - Action: Runs Nuclei vulnerability scans

- 🟣 **nikto-scanner**
  - File: `internal/active_recon/nikto_scanner/consumer.go`
  - Consumer Group: `nikto_scanner_service`
  - Action: Runs Nikto web server scans

- 🟣 **testssl-scanner**
  - File: `internal/active_recon/testssl_scanner/consumer.go`
  - Consumer Group: `testssl_scanner_service`
  - Action: Runs TestSSL TLS/SSL scans

```
                    ┌─────────────────────┐
                    │     ingestion       │
                    │  (domain slice)     │
                    └─────────────────────┘
                              │ publishes (AFTER MongoDB persistence)
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                  domain_scan_triggers                         │
│  (triggers for active recon on domains/subdomains)           │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumes (parallel consumer groups)
                              ▼
         ┌────────────────────┼────────────────────┬────────────────────┐
         │                    │                    │                    │
         ▼                    ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  js-dependency  │  │ webtechprofiler │  │  nuclei-scanner │  │  nikto-scanner  │
│    scanner      │  │                 │  │                 │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘

         ┌────────────────────┐
         │                    │
         ▼                    ▼
┌─────────────────┐  ┌─────────────────┐
│ testssl-scanner │  │                 │
│                 │  │                 │
└─────────────────┘  └─────────────────┘
         │                    │
         └────────────────────┼─► Publish to security_findings stream
```

---

## Stream 9: `port_scan_triggers`

**Purpose:** Triggers active recon scanners on ports (published AFTER ingestion)

**Publishers:**
- 🟠 **ingestion** (port_ingestion slice)
  - File: `internal/ingestion/port_ingestion/service.go`
  - Publishes: `IPDiscoveryFinding` (with trace context from ingest_port_finding span)

**Consumers:**
- 🟣 **nuclei-scanner**
  - File: `internal/active_recon/nuclei_scanner/consumer.go`
  - Consumer Group: `nuclei_scanner_service`
  - Action: Scans discovered ports for vulnerabilities

- 🟣 **nikto-scanner**
  - File: `internal/active_recon/nikto_scanner/consumer.go`
  - Consumer Group: `nikto_scanner_service`
  - Action: Scans web ports (80, 443, 8080, etc.)

- 🟣 **testssl-scanner**
  - File: `internal/active_recon/testssl_scanner/consumer.go`
  - Consumer Group: `testssl_scanner_service`
  - Action: Scans TLS/SSL ports (443, 8443, etc.)

- 🟣 **webtechprofiler**
  - File: `internal/active_recon/webtechprofiler/consumer.go`
  - Consumer Group: `webtechprofiler_service`
  - Action: Profiles web servers on discovered ports

```
                    ┌─────────────────────┐
                    │     ingestion       │
                    │   (port slice)      │
                    └─────────────────────┘
                              │ publishes (AFTER MongoDB persistence)
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                   port_scan_triggers                          │
│        (triggers for active recon on ports)                  │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ consumes (parallel consumer groups)
                              ▼
         ┌────────────────────┼────────────────────┬────────────────────┐
         │                    │                    │                    │
         ▼                    ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  nuclei-scanner │  │  nikto-scanner  │  │ testssl-scanner │  │ webtechprofiler │
│                 │  │                 │  │                 │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │                    │
         └────────────────────┼────────────────────┼────────────────────┘
                              │
                              ▼
                   Publish to security_findings stream
```

---

## Complete System Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          SCAN COORDINATOR                                │
│                         (Automated Scheduling)                           │
└─────────────────────────────────────────────────────────────────────────┘
                              │
                              │ publishes jobs
                              ▼
         ┌────────────────────┴────────────────────┐
         │                                         │
         ▼                                         ▼
┌──────────────────────┐                ┌──────────────────────┐
│ domain_discovery_    │                │  ip_discovery_       │
│      queue           │                │      queue           │
└──────────────────────┘                └──────────────────────┘
         │                                         │
         │ consumed by                             │ consumed by
         ▼                                         ▼
┌──────────────────────┐                ┌──────────────────────┐
│  domain-discovery    │                │   port-discovery     │
│     (Shodan)         │                │   (TCP scanner)      │
└──────────────────────┘                └──────────────────────┘
         │                                         │
         │ publishes findings                      │ publishes findings
         ▼                                         ▼
┌──────────────────────┐                ┌──────────────────────┐
│ domain_discovery_    │                │  ip_discovery_       │
│     results          │                │      results         │
└──────────────────────┘                └──────────────────────┘
         │                                         │
         │ consumed by (parallel)                  │ consumed by (parallel)
         ▼                                         ▼
┌──────────────────────┐                ┌──────────────────────┐
│                      │                │                      │
│   INGESTION          │◄───────────────┤   INGESTION          │
│ (domain_ingestion)   │                │ (port_ingestion)     │
│                      │                │                      │
└──────────────────────┘                └──────────────────────┘
         │                                         │
         │ persists to MongoDB                     │ persists to MongoDB
         ▼                                         ▼
    discoveries                              discoveries
    collection                               collection
         │
         │ publishes enrichment jobs
         ▼
┌──────────────────────┐
│ discovery_enrichment_│
│      queue           │
└──────────────────────┘
         │
         │ consumed by
         ▼
┌──────────────────────┐
│ discovery-enrichment │
│ (WAF + Geolocation)  │
└──────────────────────┘
         │
         │ publishes enrichment findings
         ▼
┌──────────────────────┐
│ discovery_enrichment_│
│      results         │
└──────────────────────┘
         │
         │ consumed by
         ▼
┌──────────────────────┐
│   INGESTION          │
│(enrichment_ingestion)│
└──────────────────────┘
         │
         │ updates MongoDB
         ▼
    discoveries
    collection


┌──────────────────────┐                ┌──────────────────────┐
│ domain_discovery_    │                │  ip_discovery_       │
│     results          │                │      results         │
└──────────────────────┘                └──────────────────────┘
         │                                         │
         │ consumed by (parallel)                  │ consumed by (parallel)
         ▼                                         ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  nuclei-scanner │  │  nikto-scanner  │  │ testssl-scanner │
└─────────────────┘  └─────────────────┘  └─────────────────┘

┌─────────────────┐  ┌─────────────────┐
│ webtechprofiler │  │  js-dependency  │
│                 │  │    scanner      │
└─────────────────┘  └─────────────────┘
         │                    │
         └────────────────────┼─► publish security findings
                              ▼
                    ┌──────────────────────┐
                    │  security_findings   │
                    └──────────────────────┘
                              │
                              │ consumed by
                              ▼
                    ┌──────────────────────┐
                    │      INGESTION       │
                    │ (findings_ingestion) │
                    └──────────────────────┘
                              │
                              │ persists to MongoDB
                              ▼
                          findings
                         collection
```

---

## Service Consumer Groups

| Service                  | Consumer Group                    | Streams Consumed                                        |
|--------------------------|-----------------------------------|---------------------------------------------------------|
| domain-discovery         | `shodan_subdomain_service`        | `domain_discovery_queue`                                |
| port-discovery           | `port_discovery_service`          | `ip_discovery_queue`                                    |
| ingestion (domain)       | `domain_ingestion_service`        | `domain_discovery_results`                              |
| ingestion (port)         | `port_ingestion_service`          | `ip_discovery_results`                                  |
| ingestion (findings)     | `findings_ingestion_service`      | `security_findings`                                     |
| ingestion (enrichment)   | `enrichment_ingestion_service`    | `discovery_enrichment_results`                          |
| nuclei-scanner           | `nuclei_scanner_service`          | `domain_scan_triggers`, `port_scan_triggers`            |
| nikto-scanner            | `nikto_scanner_service`           | `domain_scan_triggers`, `port_scan_triggers`            |
| testssl-scanner          | `testssl_scanner_service`         | `domain_scan_triggers`, `port_scan_triggers`            |
| webtechprofiler          | `webtechprofiler_service`         | `domain_scan_triggers`, `port_scan_triggers`            |
| js-dependency-scanner    | `js_dependency_scanner_service`   | `domain_scan_triggers`                                  |
| discovery-enrichment     | `discovery_enrichment_service`    | `discovery_enrichment_queue`                            |

---

## Key Architecture Patterns

### 1. Separation of Ingestion and Active Scanning (NEW)
**Discovery results** streams are consumed ONLY by ingestion services:
- **domain_discovery_results** → consumed ONLY by domain_ingestion
- **ip_discovery_results** → consumed ONLY by port_ingestion

**Scan trigger** streams are published AFTER ingestion and consumed by active recon scanners:
- **domain_scan_triggers** → published by domain_ingestion, consumed by 5 active recon scanners
- **port_scan_triggers** → published by port_ingestion, consumed by 4 active recon scanners

**Benefits:**
- ✅ Proper trace hierarchy (scanners are children of ingestion spans)
- ✅ Clear separation: ingestion → persistence → active scanning
- ✅ Prevents race conditions (scanners only run AFTER persistence)

### 2. Parallel Consumer Group Pattern
Multiple services consume from the same stream using different consumer groups:
- **domain_scan_triggers** → consumed by 5 active recon scanners
- **port_scan_triggers** → consumed by 4 active recon scanners

### 3. Dual-Stream Consumer Pattern
Some scanners consume from TWO trigger streams:
- **nuclei-scanner** → consumes from domain_scan_triggers AND port_scan_triggers
- **nikto-scanner** → consumes from domain_scan_triggers AND port_scan_triggers
- **testssl-scanner** → consumes from domain_scan_triggers AND port_scan_triggers
- **webtechprofiler** → consumes from domain_scan_triggers AND port_scan_triggers

### 4. Centralized Ingestion Pattern
**Only the ingestion service writes to MongoDB**:
- Discovery services publish findings to Redis
- Ingestion service persists to MongoDB
- Active recon scanners publish findings to Redis
- Ingestion service persists to MongoDB

### 5. Hierarchical Job Publishing
Services trigger downstream jobs:
- **scan-coordinator** → publishes to domain_discovery_queue + ip_discovery_queue
- **ingestion (domain)** → publishes to ip_discovery_queue + discovery_enrichment_queue + domain_scan_triggers
- **ingestion (port)** → publishes to port_scan_triggers
- **discovery-enrichment** → publishes to discovery_enrichment_results

---

## Stream Retention Policies

| Stream                           | MAXLEN | Retention Policy                        |
|-------------------------------------|--------|-----------------------------------------|
| domain_discovery_queue              | 0      | No limit (job queue)                    |
| domain_discovery_results            | 10,000 | Last 10,000 findings                    |
| ip_discovery_queue                  | 0      | No limit (job queue)                    |
| ip_discovery_results                | 10,000 | Last 10,000 findings                    |
| security_findings                   | 20,000 | Last 20,000 findings                    |
| discovery_enrichment_queue          | 0      | No limit (job queue)                    |
| discovery_enrichment_results        | 5,000  | Last 5,000 enrichments                  |
| **domain_scan_triggers**            | 10,000 | Last 10,000 triggers                    |
| **port_scan_triggers**              | 10,000 | Last 10,000 triggers                    |

**Note:** Job queues (MAXLEN=0) should NOT be trimmed to prevent job loss. Result streams and trigger streams are trimmed for memory management.
