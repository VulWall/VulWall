# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Engine is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (discovery services, scanners) is implemented as an independent service that can be compiled and deployed separately, while sharing common infrastructure code.

**Key architectural principles:**
- Discovery services focus on finding assets and publish findings to Redis streams
- The **ingestion service** uses **vertical slice architecture** with concurrent consumers
- All jobs MUST include `org_id` (organization GUID) or they will be skipped
- **Org-scoped asset storage:** ALL assets (domains, subdomains, IPs, ports) stored in single `discoveries` collection WITH `org_id`
- **Type discrimination:** Uses `asset_type` field (domain, subdomain, ip, port) to distinguish asset types
- **Denormalized design:** Each organization has separate discovery records (no cross-org deduplication)
- **Hierarchical relationships:** Domain → Subdomain → IP → Port via parent_id fields (org-scoped)
- **Two status fields:** `discovery.status` (technical state: active/inactive) and `discovery.ownership_status` (organizational state: verified/notMine/notSure)

## Project Structure

```
VulWall.NightWatch/
├── cmd/                    # Entry points for each service
│   ├── discoveries/        # Discovery services entry points
│   │   ├── domain-discovery/
│   │   │   └── main.go
│   │   └── port-discovery/
│   │       └── main.go
│   ├── active_recon/       # Active recon services entry points
│   │   ├── nuclei-scanner/
│   │   │   └── main.go
│   └── ingestion/          # Ingestion orchestrator entry point
│       └── main.go
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── bootstrap/     # Common service bootstrapping
│   │   ├── config/        # Configuration loader
│   │   ├── logger/        # Zap logger setup
│   │   ├── mongox/        # MongoDB connection
│   │   └── redisx/        # Redis client & consumer groups
│   ├── shared/            # Cross-cutting concerns used by 2+ services
│   │   ├── models.go      # Shared models (DiscoveryJob, IPDiscoveryJob, etc.)
│   │   └── constants.go   # Shared constants (streams, protocols, statuses)
│   ├── ingestion/         # Ingestion service (vertical slice architecture)
│   │   ├── orchestrator.go      # Runs all consumers concurrently
│   │   ├── domain_ingestion/    # Domain ingestion slice
│   │   │   ├── constants.go     # Consumer group
│   │   │   ├── service.go       # discoveries persistence (domains, subdomains, IPs with org_id)
│   │   │   └── consumer.go      # Consumes domain_discovery_results
│   │   ├── port_ingestion/      # Port ingestion slice
│   │   │   ├── constants.go     # Consumer group
│   │   │   ├── service.go       # discoveries persistence (ports with org_id)
│   │   │   └── consumer.go      # Consumes ip_discovery_results
│   │   └── findings_ingestion/  # Findings ingestion slice
│   │       ├── constants.go     # Consumer group
│   │       ├── service.go       # findings persistence (security vulnerabilities)
│   │       └── consumer.go      # Consumes security_findings
│   ├── discoveries/       # Discovery services (no MongoDB access)
│   │   ├── domain_discovery/   # Shodan domain discovery
│   │   │   ├── constants.go    # Consumer group name only
│   │   │   ├── service.go      # Discovery logic
│   │   │   ├── consumer.go     # Redis consumer
│   │   │   └── shodan/         # Shodan-specific client
│   │   │       └── client.go   # Shodan API client
│   │   └── port_discovery/     # Port scanner
│   │       ├── constants.go    # Consumer group + common ports array
│   │       ├── service.go      # Port scanning logic
│   │       ├── consumer.go     # Redis consumer
│   │       └── services/       # Simple TCP scanner
│   │           └── port_scanner.go  # TCP connect with 2s timeout
│   └── active_recon/      # Active reconnaissance services
│       ├── nuclei_scanner/     # Nuclei vulnerability scanner
│       │   ├── constants.go    # Consumer group
│       │   ├── models.go       # Nuclei output models
│       │   ├── service.go      # Nuclei scanning logic
│       │   └── consumer.go     # Dual-stream consumer (domain + IP results)
│       ├── nikto_scanner/      # Nikto web scanner
│       │   ├── constants.go    # Consumer group
│       │   ├── models.go       # Nikto output models
│       │   ├── service.go      # Nikto scanning logic
│       │   └── consumer.go     # Consumes domain_discovery_results
│       ├── testssl_scanner/    # TestSSL TLS/SSL scanner
│       │   ├── constants.go    # Consumer group
│       │   ├── models.go       # TestSSL output models
│       │   ├── service.go      # TestSSL scanning logic
│       │   └── consumer.go     # Consumes domain_discovery_results
│       ├── webtechprofiler/    # Web technology profiler
│       │   ├── constants.go    # Consumer group
│       │   ├── models.go       # Profiler output models
│       │   ├── service.go      # Profiling logic
│       │   └── consumer.go     # Consumes domain_discovery_results
│       └── discovery_enrichment/  # Discovery enrichment (WAF + IP geolocation)
│           ├── constants.go       # Consumer groups (domain + IP streams)
│           ├── models.go          # EnrichmentTarget model
│           ├── service.go         # Enrichment orchestrator (WAF + geolocation)
│           ├── consumer.go        # Dual-stream consumer (domain + IP results)
│           ├── waf/
│           │   └── patterns/      # WAF detection patterns
│           │       ├── detector.go      # WAF detection logic
│           │       ├── signatures.go    # 68 WAF signature patterns
│           │       └── waf_rules.json   # WAF rules (JSON format)
│           └── geolocation/
│               └── enricher.go    # IP geolocation (MaxMind MMDB)
├── ops/                   # Docker and deployment files
│   ├── active_recon/
│   │   └── nuclei-scanner/
│   │       └── Dockerfile
│   ├── domain-discovery/
│   │   └── Dockerfile
│   ├── port-discovery/
│   │   └── Dockerfile
│   ├── ingestion/
│   │   └── Dockerfile
│   ├── scripts/           # Deployment scripts
│   └── docker-compose.yml
├── scripts/               # Test and utility scripts
├── bin/                   # Compiled binaries (gitignored)
├── .env.example
├── Makefile
└── go.mod
```

**Note**: This is infrastructure-focused. No `pkg/` directory yet - external packages will be added when integrating actual scanning tools.

## Architecture Pattern

This project uses **Vertical Slice Architecture** with a **centralized ingestion layer**:

### Core Principles

1. **Discovery services** (in `internal/discoveries/`) consume jobs from Redis streams:
   - Domain discovery: consumes from `domain_discovery_queue`
   - Port discovery: consumes from `ip_discovery_queue`
2. Discovery services MUST validate `org_id` is present - skip jobs without it
3. Discovery services perform scanning/discovery logic (NO MongoDB access)
4. Discovery services publish findings to Redis result streams with `org_id` and `source`
5. **Ingestion service** (in `internal/ingestion/`) is the ONLY service that writes to MongoDB
6. Ingestion service uses **vertical slice architecture** with concurrent consumers:
   - `domain_ingestion` - processes domain/subdomain/IP discoveries → `discoveries` collection (with org_id)
   - `port_ingestion` - processes port discoveries → `discoveries` collection (with org_id)
7. Each ingestion slice MUST validate `source` is present - skip findings without it
8. **Database design:**
   - `discoveries` - Org-scoped asset registry (includes org_id) with 4 asset types: domain, subdomain, ip, port
   - Same physical asset can have multiple records (one per organization)
   - Parent ID hierarchy (org-scoped): domain (parent_id=null) → subdomain (parent_id=domain_id) → ip (parent_id=domain/subdomain_id) → port (parent_id=ip_id)

### Directory Organization

- `internal/core/` - Shared infrastructure (Redis, MongoDB, logging, config, bootstrap)
- `internal/shared/` - Models and constants used by 2+ services
- `internal/discoveries/` - Discovery services (publish findings, no MongoDB)
- `internal/ingestion/` - Ingestion service (MongoDB persistence layer)
- `cmd/` - Entry points for each service
- `ops/` - Docker and deployment files

### Communication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Discovery Architecture                       │
└─────────────────────────────────────────────────────────────────┘

DOMAIN DISCOVERY FLOW:
1. Job Published to domain_discovery_queue (with org_id)
   └─→ Consumed by domain discovery service

2. Domain Discovery Service (Shodan)
   ├─→ Finds subdomains and resolves IPs
   └─→ Publishes to domain_discovery_results (source="shodan")

3. Domain Ingestion Consumer
   └─→ Persists to discoveries collection (with org_id):
       ├─→ Domains/subdomains: tracks IP resolution history (asset_type: domain/subdomain)
       └─→ IPs: separate records with parent_id (asset_type: ip)

PORT DISCOVERY FLOW:
1. Job Published to ip_discovery_queue (with org_id)
   └─→ Consumed by port discovery service

2. Port Discovery Service
   ├─→ Scans 23 common ports (TCP connect, 2s timeout)
   └─→ Publishes to ip_discovery_results (source="port_discovery")

3. Port Ingestion Consumer
   └─→ Persists to discoveries collection (with org_id):
       ├─→ Ensures IP record exists (asset_type: "ip")
       └─→ Creates/updates port records (asset_type: "port")
           ├─→ Tracks service changes in previous_services array
           └─→ Stores banner, service_name, product, version

SECURITY FINDINGS FLOW (NUCLEI SCANNER):
1. Nuclei Scanner Consumes from TWO streams:
   ├─→ domain_discovery_results (domains/subdomains/IPs)
   └─→ ip_discovery_results (ports)

2. Nuclei Scanner Service
   ├─→ Runs Nuclei vulnerability scan on each discovered asset
   ├─→ Parses Nuclei JSON output
   └─→ Publishes to security_findings stream (source="nuclei")

3. Findings Ingestion Consumer
   └─→ Persists to findings collection:
       ├─→ Deduplicates by (org_id, discovery_id, finding_type, title)
       ├─→ Updates last_detected timestamp on duplicates
       ├─→ Reopens resolved findings if detected again
       └─→ Stores full Nuclei metadata

DISCOVERY ENRICHMENT FLOW (WAF + IP GEOLOCATION):
1. Discovery Enrichment Service Consumes from TWO streams:
   ├─→ domain_discovery_results (domains/subdomains/IPs)
   └─→ ip_discovery_results (ports on IPs)

2. Discovery Enrichment Service (filters by asset_type)
   ├─→ Domain/Subdomain assets:
   │   ├─→ IP Geolocation: Enriches with continent, country, ISP (MaxMind MMDB)
   │   └─→ WAF Detection: Sends HTTP probes (normal + attack payloads)
   │       ├─→ Analyzes responses against 68 WAF signature patterns
   │       └─→ Detects WAF vendor (Cloudflare, Akamai, AWS WAF, etc.)
   ├─→ IP assets:
   │   └─→ IP Geolocation: Enriches with continent, country, ISP
   └─→ Port assets:
       └─→ Skipped (no enrichment needed)

3. Discovery Enrichment Service publishes to discovery_enrichment_results stream:
   ├─→ Geolocation enrichment (enrichment_type="geolocation", source="discovery_enrichment")
   └─→ WAF enrichment (enrichment_type="waf", source="discovery_enrichment")

4. Enrichment Ingestion Consumer
   └─→ Updates discoveries collection:
       ├─→ Sets metadata.waf = "WAF_Name" (simple string, overwrites on change)
       └─→ Sets metadata.continent, metadata.country, metadata.isp (geolocation data)

INGESTION SERVICE ARCHITECTURE:
├─→ Orchestrator starts FOUR consumers concurrently
├─→ domain_ingestion: consumes domain_discovery_results
├─→ port_ingestion: consumes ip_discovery_results
├─→ findings_ingestion: consumes security_findings
└─→ enrichment_ingestion: consumes discovery_enrichment_results
```

### Model Ownership Rules

**Models belong in `internal/shared/` when used by multiple services:**

✅ **Put in `internal/shared/models.go`:**
- Models used by 2+ services
- Shared job formats:
  - `DiscoveryJob` (domain discovery jobs)
  - `IPDiscoveryJob` (port discovery jobs)
- Shared finding formats:
  - `DiscoveryFinding` (domain discovery findings)
  - `IPDiscoveryFinding` (port discovery findings)
  - `SecurityFinding` (security vulnerabilities from scanners)
  - `EnrichmentFinding` (asset enrichment data from active recon)
- Shared asset models:
  - `Discovery` (unified asset model for all 4 types with org_id: domain, subdomain, ip, port)
  - `ResolutionHistoryEntry` (IP resolution history for domains/subdomains)
  - `ServiceHistoryEntry` (service change history for ports)
- Common data structures for inter-service communication

✅ **Put in `internal/shared/constants.go`:**
- Shared stream names:
  - `StreamDomainDiscoveryQueue`, `StreamDomainDiscoveryResults`
  - `StreamIPDiscoveryQueue`, `StreamIPDiscoveryResults`
  - `StreamSecurityFindings` - Security findings from scanners
  - `StreamDiscoveryEnrichmentResults` - Discovery enrichment data (WAF + IP geolocation)
- Shared collection names:
  - `CollectionDiscoveries` - Org-scoped asset registry (includes org_id)
  - `CollectionFindings` - Security findings/vulnerabilities
- Asset type constants (domain, subdomain, ip, port)
- Finding severity constants (info, low, medium, high, critical)
- Finding status constants (open, resolved)
- Protocol/status constants used by multiple services
- Discovery asset status (technical state: active, inactive, unknown)
- Org asset link status (organizational state: confirmed, pending, dismissed)
- Target type constants

✅ **Put in `internal/discoveries/[service_name]/`:**
- Models used ONLY by that discovery service
- Service-specific business logic types
- Constants specific to that service (e.g., consumer group names, common ports array)

✅ **Put in `internal/ingestion/[slice_name]/`:**
- Slice-specific constants (consumer group names)
- NO models needed (uses shared models)

❌ **DO NOT put in shared:**
- Models used by only one service
- Service-specific domain logic

**Rule of thumb:** *If a model or constant is used by 2+ services, put it in `shared/`. Otherwise, keep it in the service directory.*

### Discovery Service Architecture

Discovery services use a **parallel consumer group pattern** where multiple independent services listen to the same input stream with different consumer groups, then publish to a shared output stream:

```
Input Stream: domain_discovery_queue
    ↓
    ├─→ Consumer Group: shodan_subdomain_service  → Shodan Discovery Service
    ├─→ Consumer Group: nmap_discovery_service    → Nmap Discovery Service (future)
    └─→ Consumer Group: masscan_discovery_service → Masscan Discovery Service (future)
        ↓
        All publish findings to: domain_discovery_results
        ↓
    Ingestion Service → MongoDB (discoveries collection with org_id)
```

**Key Benefits:**
- ✅ Each discovery tool is an independent service
- ✅ All services process the same job simultaneously
- ✅ Scale each tool independently (e.g., 5 Shodan workers, 2 Nmap workers)
- ✅ Deploy/update tools independently
- ✅ Easy to add new discovery tools
- ✅ **Single source of truth for MongoDB** (ingestion service only)
- ✅ Discovery services focus on discovery logic only
- ✅ Clear separation of concerns

**How it works:**
1. Publisher sends job to `domain_discovery_queue` stream (MUST include `org_id`)
2. **All** discovery services receive the same job (different consumer groups)
3. Each service validates `org_id` is present (skip if missing)
4. Each service processes the job with its own tool (Shodan, Nmap, etc.)
5. Each service publishes findings to `domain_discovery_results` stream with `org_id` and `source` field
6. Ingestion service consumes from `domain_discovery_results`
7. Ingestion service validates `source` is present (skip if missing)
8. Ingestion service processes all domain/subdomain discoveries:
   - Domains/subdomains → `discoveries` (asset_type: "domain" or "subdomain", with org_id) with IP resolution history
   - IPs → `discoveries` (asset_type: "ip", with org_id) as separate records with parent_id
   - All assets include org_id, ownership_status (verified/notMine/notSure), and assigned_at timestamp

## Common Commands

### Building Services
```bash
make build                      # Build all services
make build-domain-discovery     # Build domain-discovery only
make build-port-discovery       # Build port-discovery only
make build-nuclei-scanner       # Build nuclei-scanner only
make build-ingestion            # Build ingestion only
```

### Running Locally
```bash
make run-domain-discovery       # Run domain-discovery service
make run-port-discovery         # Run port-discovery service
make run-nuclei-scanner         # Run nuclei-scanner service
make run-ingestion              # Run ingestion service (all consumers)
```

### Docker Operations
```bash
make docker-up                         # Start all services
make docker-down                       # Stop all services
make docker-scale-domain-discovery N=2 # Scale domain-discovery workers to 2
make docker-scale-port-discovery N=5   # Scale port-discovery workers to 5
make docker-scale-nuclei-scanner N=3   # Scale nuclei-scanner workers to 3
make docker-scale-ingestion N=3        # Scale ingestion workers to 3
make docker-logs                       # View logs
```

### Testing
```bash
make test                   # Run all tests
make test-coverage          # Run tests with coverage report
```

### Code Quality
```bash
make fmt                    # Format code
make lint                   # Run linter
make vet                    # Run go vet
make deps                   # Download and tidy dependencies
```

## Adding a New Discovery Service

When adding a new discovery tool (e.g., `nmap_discovery`):

1. **Create service directory:**
   ```bash
   mkdir -p internal/discoveries/nmap_discovery
   ```

2. **Create constants (consumer group only):**
   ```bash
   # internal/discoveries/nmap_discovery/constants.go
   package nmap_discovery

   const (
       // Nmap-specific consumer group
       // Stream names are in shared.StreamDomainDiscoveryQueue and shared.StreamDomainDiscoveryResults
       GroupNmapDiscovery = "nmap_discovery_service"
   )
   ```

3. **Create service.go (NO MongoDB dependency):**
   ```go
   package nmap_discovery

   import (
       "context"
       "encoding/json"
       "github.com/go-redis/redis/v8"
       "github.com/vulwall/scanners/internal/ingestion"
       "github.com/vulwall/scanners/internal/shared"
   )

   type Service struct {
       redis      *redis.Client
       logger     *zap.Logger
       nmapClient *nmap.Client
   }

   func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
       // 1. Run nmap scan on job.Host
       // 2. For each discovered port/service, publish finding to domain_discovery_results
       // 3. Use ingestion.DiscoveryFinding model with source="nmap"
       finding := ingestion.DiscoveryFinding{
           TraceID:  job.TraceID,
           Source:   "nmap",
           Host:     job.Host,
           Port:     &discoveredPort,
           Protocol: &protocol,
           Status:   shared.AssetStatusActive,
           Metadata: map[string]interface{}{"service": serviceName},
           Timestamp: time.Now(),
       }
       return s.publishFinding(ctx, finding)
   }

   func (s *Service) publishFinding(ctx context.Context, finding ingestion.DiscoveryFinding) error {
       data, _ := json.Marshal(finding)
       _, err := s.redis.XAdd(ctx, &redis.XAddArgs{
           Stream: shared.StreamDiscoveries,
           Values: map[string]interface{}{"data": string(data)},
       }).Result()
       return err
   }
   ```

4. **Create consumer.go:**
   ```go
   package nmap_discovery

   // Consumer reads from shared.StreamDiscovery
   // Calls service.ProcessJob()
   // NO MongoDB access
   ```

5. **Create entry point:**
   ```bash
   mkdir -p cmd/nmap-discovery
   # cmd/nmap-discovery/main.go
   ```

   ```go
   package main

   import (
       "github.com/vulwall/scanners/internal/core/bootstrap"
       "github.com/vulwall/scanners/internal/shared"
       "github.com/vulwall/scanners/internal/discoveries/nmap_discovery"
   )

   func main() {
       bootstrap.Run(bootstrap.ServiceConfig{
           ServiceName:   "nmap-discovery",
           StreamName:    shared.StreamDomainDiscoveryQueue,
           ConsumerGroup: nmap_discovery.GroupNmapDiscovery,
           Factory: func(cfg *config.Config, redisClient *redis.Client, _ *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
               return nmap_discovery.NewConsumer(redisClient, logger)
           },
       })
   }
   ```

6. **Add Docker support:**
   - Create `ops/Dockerfile.nmap-discovery`
   - Add to `ops/docker-compose.yml`
   - Update `Makefile` with build/run/scale targets

**Key Points:**
- ✅ Use `shared.StreamDomainDiscoveryQueue` (input stream)
- ✅ Use `shared.StreamDomainDiscoveryResults` (output stream)
- ✅ Use unique consumer group per tool (e.g., `nmap_discovery_service`)
- ✅ Use `shared.DiscoveryJob` for input
- ✅ Use `shared.DiscoveryFinding` for output
- ✅ **NO MongoDB dependency** in discovery services
- ✅ Publish findings with `source` field ("nmap", "shodan", etc.)

## Discovery Enrichment (WAF Detection + IP Geolocation)

The project supports **discovery enrichment** - adding metadata to discovered assets without creating separate findings. The discovery enrichment service combines two enrichment types: **WAF detection** (identifies Web Application Firewalls) and **IP geolocation** (enriches IPs with geographic data).

### Discovery Enrichment Architecture

**Location:** `internal/active_recon/discovery_enrichment/`

**How it works:**
1. Consumes from TWO Redis streams in parallel:
   - `domain_discovery_results` (domains/subdomains/IPs)
   - `ip_discovery_results` (ports on IPs)
2. Filters by `asset_type` field to determine enrichment strategy:
   - **Domain/Subdomain:** IP geolocation + WAF detection
   - **IP:** IP geolocation only
   - **Port:** Skip (no enrichment needed)
3. Publishes enrichment findings to `discovery_enrichment_results` stream

**Components:**

**WAF Detection** (`waf/patterns/`):
- Sends HTTP probes (normal request + 10 attack payloads: XSS, SQLi, LFI, etc.)
- Analyzes responses against 68 WAF signature patterns (ported from wafw00f)
- Publishes WAF enrichment if detected

**IP Geolocation** (`geolocation/`):
- Uses MaxMind MMDB database for IP lookups
- Extracts continent, country, ISP information
- Publishes geolocation enrichment for all IPs

**WAF Signatures:** Located in `internal/active_recon/discovery_enrichment/waf/patterns/signatures.go`

Detects 68 WAF vendors including:
- **Cloud WAFs:** Cloudflare, Akamai, AWS WAF, Azure Front Door, Google Cloud Armor, ZScaler, Fastly
- **Enterprise WAFs:** F5 BIG-IP, Imperva Incapsula, Fortinet FortiWeb, Citrix NetScaler, IBM WebSEAL, IBM DataPower
- **European WAFs:** Airlock (Swiss), NevisProxy (Swiss), TransIP (Netherlands), Link11 (German), WatchGuard
- **Open Source:** ModSecurity, NAXSI, LiteSpeed
- **Security SaaS:** Sucuri, Wordfence, PerimeterX, Wallarm, Reblaze
- **Regional Asia:** Jiasule, Yundun, SafeDog, West263CDN, ChinaCache, Huawei Cloud, Tencent Cloud
- **Regional EU/Russia:** Qrator, PT Application Firewall, HyperGuard, GreyWizard
- **WordPress Plugins:** NinjaFirewall (French), WebARX, Shield Security
- **Microsoft IIS:** URLScan, RequestValidationMode

**Detection Logic:** Each signature defines checks for:
- **Headers:** Specific header names/values (e.g., `CF-Ray`, `X-Akamai-Request-ID`)
- **Cookies:** Cookie name patterns (e.g., `__cfduid`, `incap_ses_`)
- **Content:** Body text patterns (e.g., "Access Denied by Cloudflare")
- **Status codes:** Block responses (403, 406, 418, 503, etc.)

A match requires **at least 2 checks** to pass for confidence.

### Enrichment Ingestion

**Location:** `internal/ingestion/enrichment_ingestion/`

**How it works:**
1. Consumes from `discovery_enrichment_results` stream
2. Validates `source` is present (skips if missing)
3. Updates discovery in MongoDB based on `enrichment_type`:
   - **Type: "waf"** → Sets `metadata.waf = "Cloudflare"` (simple string)
   - **Type: "geolocation"** → Sets `metadata.continent`, `metadata.country`, `metadata.isp`
4. Overwrites previous values (no history tracking per user requirements)

**Data Model:**
```javascript
// Before enrichment
{
  _id: "uuid-123",
  org_id: "org-456",
  asset_type: "domain",
  domain: "example.com",
  metadata: {}
}

// After discovery enrichment (WAF + geolocation)
{
  _id: "uuid-123",
  org_id: "org-456",
  asset_type: "domain",
  domain: "example.com",
  metadata: {
    waf: "Cloudflare",           // ← WAF detection result
    continent: "North America",   // ← IP geolocation
    country: "United States",     // ← IP geolocation
    isp: "Cloudflare, Inc."      // ← IP geolocation
  }
}
```

### Query Examples

**Find assets with specific WAF:**
```javascript
db.discoveries.find({
  org_id: "org-456",
  "metadata.waf": "Cloudflare"
})
```

**Find assets with ANY WAF:**
```javascript
db.discoveries.find({
  org_id: "org-456",
  "metadata.waf": {$exists: true, $ne: null}
})
```

**Find unprotected assets (security risk!):**
```javascript
db.discoveries.find({
  org_id: "org-456",
  asset_type: {$in: ["domain", "subdomain"]},
  $or: [
    {"metadata.waf": {$exists: false}},
    {"metadata.waf": null}
  ]
})
```

**Find high-severity findings on non-WAF-protected assets:**
```javascript
db.findings.aggregate([
  {$match: {org_id: "org-456", severity: "high"}},
  {$lookup: {
    from: "discoveries",
    localField: "discovery_id",
    foreignField: "_id",
    as: "asset"
  }},
  {$match: {"asset.metadata.waf": {$in: [null, ""]}}}
])
```

**Find assets by country (geolocation):**
```javascript
db.discoveries.find({
  org_id: "org-456",
  "metadata.country": "United States"
})
```

**Find assets by ISP:**
```javascript
db.discoveries.find({
  org_id: "org-456",
  "metadata.isp": /cloudflare/i  // Case-insensitive regex match
})
```

### Adding New Enrichment Types

To add a new enrichment type (e.g., CDN detection, tech stack profiling):

**Option 1: Add to existing discovery_enrichment service**
1. **Add enrichment logic to service.go:**
   - Add new enrichment method (e.g., `enrichCDN()`)
   - Call it from `ProcessEnrichment()` based on asset_type
   - Publish `EnrichmentFinding` with your `enrichment_type`

2. **Update enrichment ingestion:**
   - Add case in `enrichment_ingestion/service.go`:
     ```go
     case "cdn":
         return s.processCDNEnrichment(ctx, enrichment)
     ```

**Option 2: Create separate enrichment service**
1. **Create active recon service:**
   - Follow discovery_enrichment pattern in `internal/active_recon/`
   - Consume from appropriate discovery stream(s)
   - Filter by asset_type if needed
   - Publish `EnrichmentFinding` with your `enrichment_type`

2. **Update enrichment ingestion:**
   - Add case in `enrichment_ingestion/service.go`:
     ```go
     case "tech_stack":
         return s.processTechStackEnrichment(ctx, enrichment)
     ```

**Storage Guidelines:**
- Use simple types: string, number, boolean, or simple objects
- Avoid arrays or complex history tracking
- Example: `metadata.cdn = "Cloudflare"`, `metadata.cms = "WordPress"`

## Key Files

### Infrastructure (`internal/core/`)
- `bootstrap/bootstrap.go` - Common service initialization pattern (eliminates boilerplate)
- `config/config.go` - Environment-based configuration loader
- `logger/logger.go` - Zap logger initialization
- `redisx/client.go` - Redis client with consumer group helpers
- `mongox/client.go` - MongoDB connection manager

### Shared Package (`internal/shared/`)
- `models.go` - Models used by 2+ services:
  - Job formats: `DiscoveryJob`, `IPDiscoveryJob`
  - Finding formats: `DiscoveryFinding`, `IPDiscoveryFinding`
  - Asset models: `Discovery` (unified model for all 4 asset types)
  - Relationship model: `OrgAssetLink`
  - History models: `ResolutionHistoryEntry`, `ServiceHistoryEntry`
- `constants.go` - Constants used by 2+ services (streams, collections, asset types, protocols, statuses)

### Ingestion Service (`internal/ingestion/`)
**Domain Ingestion Slice** (`internal/ingestion/domain_ingestion/`):
- `constants.go` - Consumer group name
- `service.go` - MongoDB persistence for domains, subdomains, and IPs (with org_id):
  - `upsertDomainDiscovery()` - Creates/updates domains or subdomains with IP resolution history (org-scoped)
  - `upsertIPDiscovery()` - Creates/updates IP records with parent_id (org-scoped)
  - `publishIPDiscoveryJob()` - Triggers port scanning for new IPs
- `consumer.go` - Redis consumer for domain_discovery_results stream

**Port Ingestion Slice** (`internal/ingestion/port_ingestion/`):
- `constants.go` - Consumer group name
- `service.go` - MongoDB persistence for ports (with org_id):
  - `ensureIPDiscovery()` - Ensures IP record exists (org-scoped)
  - `upsertPortDiscovery()` - Creates/updates port records with service tracking (org-scoped)
  - `updatePortDiscovery()` - Tracks service changes in previous_services array
- `consumer.go` - Redis consumer for ip_discovery_results stream

### Discovery Service Pattern (`internal/discoveries/[service_name]/`)
Each discovery service is self-contained:
```
internal/discoveries/[service_name]/
├── constants.go   # Consumer group name
├── service.go     # Discovery logic, publishes findings to Redis
├── consumer.go    # Redis consumer, reads jobs from domain_discovery_queue
├── models.go      # Optional: service-specific models
└── [tool]/        # Tool-specific implementation (client, API wrappers, etc.)
    └── client.go
```

### Shared Models

**DiscoveryJob** - Common job format for all discovery services (input):
```go
type DiscoveryJob struct {
    TraceID  string                 // Request tracing
    ScanID   *string                // Optional: scan identifier for linking to UI scans
    OrgID    string                 // REQUIRED: organization GUID (validated by consumers)
    ParentID *string                // Parent asset ID (for recursive discovery)
    Host     string                 // Domain or IP to discover
    Port     *int                   // Optional: specific port to scan
    Protocol *string                // Optional: tcp, udp, sctp, icmp
    Metadata map[string]interface{} // Provider-specific metadata
    Created  time.Time
}
```

**⚠️ IMPORTANT:** Discovery consumers MUST validate `org_id` is present and skip jobs without it.
**Note:** `scan_id` is optional - supports both UI-initiated scans (with scan_id) and automated/background scans (without scan_id).

**DiscoveryFinding** - Common finding format published by all discovery services (output):
```go
type DiscoveryFinding struct {
    TraceID   string                 // Request tracing
    ScanID    *string                // Optional: scan identifier for linking to UI scans
    OrgID     string                 // REQUIRED: organization GUID (passed from job)
    Source    string                 // REQUIRED: "shodan", "nmap", "masscan", etc. (validated by ingestion)
    ParentID  *string                // Parent asset ID
    Host      string                 // Domain or IP
    IP        *string                // Resolved IP address (Shodan includes this)
    Port      *int                   // Optional port number
    Protocol  *string                // tcp, udp, sctp, icmp (nil for non-port assets)
    Status    string                 // active, inactive, unknown
    Metadata  map[string]interface{} // Source-specific data
    Timestamp time.Time              // When finding was discovered
}
```

**⚠️ IMPORTANT:** Ingestion service MUST validate `source` is present and skip findings without it.

**IPDiscoveryJob** - Job format for port discovery services (input):
```go
type IPDiscoveryJob struct {
    TraceID   string                 // Request tracing
    ScanID    *string                // Optional: scan identifier for linking to UI scans
    OrgID     string                 // REQUIRED: organization GUID (validated by consumers)
    ParentID  *string                // Parent asset ID
    IP        string                 // Target IP address
    PortRange *string                // Optional: "1-1000" or "80,443,22"
    Metadata  map[string]interface{} // Provider-specific metadata
    Created   time.Time
}
```

**IPDiscoveryFinding** - Finding format published by port discovery services (output):
```go
type IPDiscoveryFinding struct {
    TraceID     string                 // Request tracing
    ScanID      *string                // Optional: scan identifier for linking to UI scans
    OrgID       string                 // REQUIRED: organization GUID (passed from job)
    Source      string                 // REQUIRED: "port_discovery", etc. (validated by ingestion)
    ParentID    *string                // Parent asset ID
    IP          string                 // Target IP
    Port        int                    // Discovered port number
    Protocol    string                 // tcp, udp
    Status      string                 // active, inactive
    Banner      *string                // Service banner (optional)
    ServiceName *string                // Service name (e.g., "http", "ssh") (optional)
    Product     *string                // Product name (e.g., "Apache", "nginx") (optional)
    Version     *string                // Version string (e.g., "2.4.41") (optional)
    Metadata    map[string]interface{} // Source-specific data
    Timestamp   time.Time              // When finding was discovered
}
```

**Discovery** - Unified asset model with type discrimination (MongoDB `discoveries` collection):
```go
type Discovery struct {
    ID             string    // UUID (org-scoped deterministic ID)
    OrgID          string    // Organization GUID
    ScanIDs        []string  // Array of scan identifiers that detected this asset
    AssetType      string    // "domain", "subdomain", "ip", or "port" (type discrimination)
    Source         string    // Discovery source ("shodan", "port_discovery", etc.)
    Status         string    // active, inactive, unknown (technical state)
    OwnershipStatus string    // "verified", "notMine", "notSure" (organizational state)
    AssignedAt     time.Time // When assigned to this organization
    ParentID       *string   // Parent asset ID (hierarchical relationships, org-scoped)
    FirstSeen      time.Time
    LastSeen       time.Time
    Metadata       map[string]interface{} // Generic metadata for all types

    // Domain-specific fields (when asset_type = "domain")
    Domain            *string                   // Domain name (e.g., "example.com")
    ResolutionHistory []ResolutionHistoryEntry  // IP resolution history

    // Subdomain-specific fields (when asset_type = "subdomain")
    Subdomain *string // Subdomain name (e.g., "api.example.com")
    // Note: Subdomains also use ResolutionHistory

    // IP-specific fields (when asset_type = "ip")
    IP *string // IP address

    // Port-specific fields (when asset_type = "port")
    Port             *int                   // Port number
    Protocol         *string                // tcp, udp
    Banner           *string                // Service banner
    ServiceName      *string                // Service name (e.g., "http", "ssh")
    Product          *string                // Product (e.g., "Apache", "nginx")
    Version          *string                // Version (e.g., "2.4.41")
    PreviousServices []ServiceHistoryEntry  // Service change history
}

type ResolutionHistoryEntry struct {
    IP        string     // IP address
    FirstSeen time.Time  // When this IP resolution started
    LastSeen  *time.Time // When it ended (nil = currently active)
}

type ServiceHistoryEntry struct {
    ServiceName string     // Service name
    Product     *string    // Product name
    Version     *string    // Version string
    Banner      *string    // Raw service banner
    LastSeen    time.Time  // When this service was last seen
}
```

**Key Design Decisions:**
- ✅ **Org-scoped asset collection with type discrimination:**
  - `discoveries` - Org-scoped asset registry storing ALL 4 asset types (domain, subdomain, ip, port)
  - Leverages MongoDB flexible schema for type-specific fields
  - Includes org_id in every discovery (denormalized, same physical asset can have multiple records)
  - Natural parent-child hierarchy via `parent_id` (org-scoped): domain → subdomain → ip → port
- ✅ **Denormalized design:**
  - Same physical asset creates separate discovery records for each organization
  - Each org has independent copies of assets with independent statuses
  - Simplifies queries (no joins needed), but increases storage
- ✅ **Two status fields with different meanings:**
  - `discovery.status` - Technical state (active/inactive/unknown) - is the asset reachable?
  - `discovery.ownership_status` - Organizational state (verified/notMine/notSure) - does org claim this asset?
- ✅ **Hierarchical traceability (org-scoped):**
  - Domains track parent_id=null (root assets)
  - Subdomains track parent_id=domain_id (within same org)
  - IPs track parent_id=domain_id or subdomain_id (within same org)
  - Ports track parent_id=ip_id (within same org)
  - Full chain (org-scoped): port → IP → subdomain → domain
- ✅ **History tracking:**
  - Domains and subdomains: IP resolution history (tracks when IPs change)
  - Ports: Service change history (tracks when services change)
  - Scan history: `scan_ids` array tracks all scans that detected each asset
- ✅ **Scan tracking with arrays:**
  - Jobs have single `scan_id` (optional) - represents current scan execution
  - Discoveries accumulate `scan_ids` array - tracks all scans that found this asset
  - Findings accumulate `scan_ids` array - tracks all scans that detected this vulnerability
  - Uses MongoDB `$addToSet` to prevent duplicate scan IDs
  - Enables queries like "assets found in scan X" or "assets found in both scans X and Y"
- ✅ **Protocol-aware deduplication (org-scoped):**
  - `192.168.1.1:53/tcp` ≠ `192.168.1.1:53/udp` (different discoveries)
  - Assets unique by (org_id + type + identifying fields), enforced by unique indexes
- ✅ **Source tracking** - Discovery source tracked for each asset
- ✅ **Separation of concerns** - Discovery services publish, ingestion service persists

### Shared Constants

**Stream Names:**
- `shared.StreamDomainDiscoveryQueue = "domain_discovery_queue"` - Input stream for domain discovery jobs (requires `org_id`)
- `shared.StreamDomainDiscoveryResults = "domain_discovery_results"` - Output stream for domain discovery findings (requires `source`)
- `shared.StreamIPDiscoveryQueue = "ip_discovery_queue"` - Input stream for IP port discovery jobs (requires `org_id`)
- `shared.StreamIPDiscoveryResults = "ip_discovery_results"` - Output stream for IP port discovery findings (requires `source`)
- `shared.StreamSecurityFindings = "security_findings"` - Output stream for security findings from scanners (requires `source`)

**Collection Names:**
- `shared.CollectionDiscoveries = "discoveries"` - Org-scoped asset registry (all 4 asset types, includes org_id)
- `shared.CollectionFindings = "findings"` - Security findings/vulnerabilities

**Asset Types (for Discovery.AssetType):**
- `shared.AssetTypeDomain = "domain"` - Domain asset type
- `shared.AssetTypeSubdomain = "subdomain"` - Subdomain asset type
- `shared.AssetTypeIP = "ip"` - IP asset type
- `shared.AssetTypePort = "port"` - Port asset type

**Protocols:**
- `shared.ProtocolTCP`, `ProtocolUDP`, `ProtocolSCTP`, `ProtocolICMP`

**Target Types:**
- `shared.TargetTypeDomain`, `TargetTypeIP`, `TargetTypeCIDR`

**Discovery Asset Status (technical state):**
- `shared.AssetStatusActive` - Asset is live/reachable
- `shared.AssetStatusInactive` - Asset is not reachable
- `shared.AssetStatusUnknown` - Asset state is unknown

**Ownership Status (organizational state):**
- `shared.OwnershipStatusVerified = "verified"` - Asset verified to belong to org
- `shared.OwnershipStatusNotMine = "notMine"` - Asset does not belong to org
- `shared.OwnershipStatusNotSure = "notSure"` - Asset ownership unclear/pending verification

**Finding Severity Levels:**
- `shared.SeverityInfo` - Informational finding
- `shared.SeverityLow` - Low severity vulnerability
- `shared.SeverityMedium` - Medium severity vulnerability
- `shared.SeverityHigh` - High severity vulnerability
- `shared.SeverityCritical` - Critical severity vulnerability

**Finding Status:**
- `shared.FindingStatusOpen` - Finding is currently open
- `shared.FindingStatusResolved` - Finding has been resolved

### Security Findings Model

**SecurityFinding** - Represents security vulnerabilities discovered by scanning tools:
```go
type SecurityFinding struct {
    TraceID      string                 // Request tracing
    ScanID       *string                // Optional: scan identifier for linking to UI scans
    OrgID        string                 // REQUIRED: organization GUID
    Source       string                 // REQUIRED: "nuclei", etc. (validated by ingestion)
    DiscoveryID  string                 // Links to Discovery._id
    FindingType  string                 // Type of finding (e.g., "cve-2021-1234", "xss")
    Severity     string                 // info, low, medium, high, critical
    Title        string                 // Short title
    Description  string                 // Detailed description
    Metadata     map[string]interface{} // Scanner-specific data
    Status       string                 // open, resolved
    Timestamp    time.Time              // When finding was discovered
}
```

**Findings Collection Schema (MongoDB):**
```javascript
{
  _id: "uuid",
  org_id: "uuid",                  // Organization GUID
  discovery_id: "uuid",            // References discoveries._id
  finding_type: "string",          // Type identifier (template ID, CVE, etc.)
  severity: "string",              // info, low, medium, high, critical
  source: "string",                // Scanner source (e.g., "nuclei")
  title: "string",                 // Short title
  description: "string",           // Detailed description
  metadata: {},                    // Scanner-specific data (Nuclei output, etc.)
  status: "string",                // open, resolved
  scan_ids: ["string"],            // Array of scan identifiers that detected this finding
  first_detected: "date",          // When first discovered
  last_detected: "date",           // When last seen
  resolved_at: "date" (optional)   // When resolved (null if open)
}
```

**Key Design Decisions:**
- ✅ **Deduplication:** Findings deduplicated by (org_id, discovery_id, finding_type, title)
- ✅ **Temporal tracking:** Both first_detected and last_detected timestamps
- ✅ **Reopening resolved findings:** If a resolved finding is detected again, it's reopened automatically
- ✅ **Full metadata preservation:** All scanner-specific data preserved in metadata field
- ✅ **Links to assets:** discovery_id links back to the asset in discoveries collection
- ✅ **Source attribution:** Source field tracks which scanner produced the finding

## Configuration

**This project uses cloud-hosted Redis and MongoDB.** Services load config from environment variables or `.env` file:

- `REDIS_ADDR` - Cloud Redis endpoint (e.g., `redis-12345.cloud.redislabs.com:12345`)
- `REDIS_PASSWORD` - Redis authentication password (required for cloud)
- `REDIS_DB` - Redis database number (default: 0)
- `MONGO_URI` - MongoDB Atlas/Cloud connection string (e.g., `mongodb+srv://user:pass@cluster.mongodb.net/`)
- `MONGO_DB` - Database name (default: vulwall)
- `ENVIRONMENT` - development/production (affects logging)
- `SHODAN_API_KEY` - Shodan API key for subdomain discovery (domain-discovery service)

See `.env.example` for full list and examples.

## Testing Strategy

- Unit tests for service logic should mock Redis/MongoDB
- Integration tests should use testcontainers
- Each service is independent - test in isolation
- Shared core packages should have comprehensive tests

## Publishing Discovery Jobs

### Domain Discovery (Shodan)

To trigger domain discovery:

```bash
# ✅ VALID: Job with org_id and scan_id (UI-initiated scan)
redis-cli XADD domain_discovery_queue * data '{
  "trace_id": "trace-123",
  "scan_id": "scan-abc-456",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "example.com",
  "created": "2025-10-15T10:00:00Z"
}'

# ✅ ALSO VALID: Job without scan_id (automated/background scan)
redis-cli XADD domain_discovery_queue * data '{
  "trace_id": "trace-123",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "example.com",
  "created": "2025-10-15T10:00:00Z"
}'

# Result:
# 1. Domain discovery service finds subdomains and resolves IPs
# 2. Findings published to domain_discovery_results with org_id, scan_id (if provided), and source="shodan"
# 3. Domain ingestion consumer stores in discoveries collection (with org_id and scan_id):
#    - Domains/subdomains with asset_type="domain"/"subdomain", ownership_status="verified", IP resolution history
#    - IPs with asset_type="ip", ownership_status="verified", as separate records with parent_id
```

### Port Discovery (TCP Scanner)

To trigger port discovery:

```bash
# ✅ VALID: Job with org_id and scan_id (UI-initiated scan)
redis-cli XADD ip_discovery_queue * data '{
  "trace_id": "trace-456",
  "scan_id": "scan-abc-456",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip": "8.8.8.8",
  "created": "2025-10-15T10:00:00Z"
}'

# Result:
# 1. Port discovery service scans 23 common ports (TCP connect, 2s timeout)
# 2. For each open port, finding published to ip_discovery_results with scan_id and source="port_discovery"
# 3. Port ingestion consumer stores in discoveries collection (with org_id and scan_id):
#    - Ensures IP record exists with asset_type="ip", ownership_status="verified"
#    - Creates/updates port with asset_type="port", ownership_status="verified", banner, service_name, product, version
```

**❌ INVALID: Job without org_id (will be skipped):**
```bash
redis-cli XADD ip_discovery_queue * data '{
  "trace_id": "trace-789",
  "ip": "8.8.8.8",
  "created": "2025-10-15T10:00:00Z"
}'
# This job will be skipped by port discovery consumer
```

**⚠️ IMPORTANT:** All jobs MUST include `org_id` or they will be skipped by consumers.

### Querying Results

**Query all assets for an organization:**
```javascript
// Simple query - no joins needed
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000"
})
```

**Query only ports for an organization:**
```javascript
// Filter by org_id and asset_type
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  asset_type: "port"
})
```

**Query confirmed assets for an organization:**
```javascript
// Filter by org_id and organizational status
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  ownership_status: "verified"
})
```

**Query domain hierarchy (domain → subdomains → IPs → ports) for an organization:**
```javascript
// Find all subdomains of a domain (org-scoped)
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  asset_type: "subdomain",
  parent_id: "domain-uuid-here"
})

// Find all IPs resolved from a domain/subdomain (org-scoped)
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  asset_type: "ip",
  parent_id: "domain-or-subdomain-uuid-here"
})

// Find all ports on an IP (org-scoped)
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  asset_type: "port",
  parent_id: "ip-uuid-here"
})
```

**Query discoveries from a specific scan:**
```javascript
// Find all discoveries from scan-abc-456
// scan_ids is an array, so use direct value match (MongoDB handles array matching)
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  scan_ids: "scan-abc-456"
})

// Count discoveries by asset type for a scan
db.discoveries.aggregate([
  {
    $match: {
      org_id: "550e8400-e29b-41d4-a716-446655440000",
      scan_ids: "scan-abc-456"
    }
  },
  {
    $group: {
      _id: "$asset_type",
      count: { $sum: 1 }
    }
  }
])

// Find discoveries from scan, sorted by discovery time
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  scan_ids: "scan-abc-456"
}).sort({ assigned_at: -1 })

// Find all security findings from a scan
db.findings.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  scan_ids: "scan-abc-456"
})

// Find assets discovered in multiple scans (intersection)
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  scan_ids: { $all: ["scan-abc-456", "scan-xyz-789"] }
})

// Find assets discovered ONLY in latest scan (not in previous)
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  scan_ids: "scan-xyz-789",
  scan_ids: { $nin: ["scan-abc-456"] }  // Not in previous scan
})

// Compare scan results: count new vs existing assets
db.discoveries.aggregate([
  {
    $match: {
      org_id: "550e8400-e29b-41d4-a716-446655440000",
      scan_ids: "scan-xyz-789"
    }
  },
  {
    $project: {
      asset_type: 1,
      is_new: { $eq: [{ $size: "$scan_ids" }, 1] }  // Only one scan ID = new
    }
  },
  {
    $group: {
      _id: { asset_type: "$asset_type", is_new: "$is_new" },
      count: { $sum: 1 }
    }
  }
])
```

## Dependencies

- `github.com/go-redis/redis/v8` - Redis client with Streams support
- `go.mongodb.org/mongo-driver` - Official MongoDB driver
- `go.uber.org/zap` - Structured logging
- `github.com/joho/godotenv` - Environment variable management
- `github.com/google/uuid` - Consumer name generation

## Development Workflow

1. Make changes to a service (e.g., `internal/discoveries/domain_discovery/`)
2. Test locally: `make run-domain-discovery` + `make run-ingestion`
3. Verify: Publish test job to `domain_discovery_queue`, check MongoDB for results
4. Build: `make build-domain-discovery && make build-ingestion`
5. Deploy: `make docker-build && make docker-up`

## Important Notes

### Architecture
- **Each discovery service must be independent** - avoid coupling between services
- **Shared models for communication** - Use `internal/shared/` for models used by 2+ services
- **Discovery services should not access MongoDB** - only publish findings to Redis
- **Ingestion service is the single source of truth** - only it writes to MongoDB
- **Use bootstrap pattern** - All services use `bootstrap.Run()` to eliminate boilerplate

### Infrastructure
- **Cloud infrastructure** - This project uses cloud-hosted Redis and MongoDB, not self-hosted instances
- **Never commit `.env`** - only `.env.example` should be in git (contains cloud credentials)
- **Consumer groups prevent duplicate processing** - multiple workers can run safely
- **Discovery services publish to Redis** - ingestion service persists to MongoDB
- **Graceful shutdown** - Services handle SIGTERM/SIGINT properly
- **No local infrastructure needed** - All services connect to cloud databases directly

### Discovery Services Pattern
- **Organization-scoped** - All jobs require `org_id` (GUID), consumers skip jobs without it
- **Two discovery flows:**
  - **Domain discovery:** `domain_discovery_queue` → `domain_discovery_results` → `discoveries` (domain, subdomain, ip with org_id)
  - **Port discovery:** `ip_discovery_queue` → `ip_discovery_results` → `discoveries` (ip, port with org_id)
- **Independent scaling** - Scale each discovery tool independently (e.g., 5 domain workers, 10 port workers)
- **Unique consumer groups** - Each tool has its own group:
  - Domain: `shodan_subdomain_service`
  - Port: `port_discovery_service`
- **Shared models** - All use appropriate shared job/finding models
- **Source validation** - Ingestion service requires `source` field, skips findings without it
- **Vertical slice ingestion** - Each ingestion type runs concurrently:
  - **domain_ingestion** - Processes domains, subdomains, and IPs → `discoveries` (with org_id)
  - **port_ingestion** - Processes ports → `discoveries` (with org_id)
- **History tracking:**
  - Domain/subdomain ingestion tracks IP resolution changes over time
  - Port ingestion tracks service changes: archives complete service state (service_name, product, version, banner) to previous_services array when ANY characteristic changes
- **Source attribution** - Use `source` field to identify which tool discovered the asset
- **Org-scoped storage** - All assets stored with org_id in `discoveries` collection (denormalized design)
- **Type discrimination** - Single `discoveries` collection uses `asset_type` field to distinguish 4 asset types
- **Org-scoped deduplication** - Unique indexes on (org_id + asset_type + identifying fields) prevent duplicates within an org

### Example: Domain Discovery Service (Shodan)
```
internal/discoveries/domain_discovery/
├── constants.go      # GroupDomainDiscovery only
├── service.go        # Uses shared.DiscoveryJob, publishes shared.DiscoveryFinding
├── consumer.go       # Listens to shared.StreamDomainDiscoveryQueue with GroupDomainDiscovery
└── shodan/
    └── client.go     # Shodan API client implementation
```

**Domain Discovery Flow:**
1. Job published to `domain_discovery_queue` (with `org_id`)
2. Domain discovery service validates `org_id` is present (skips if missing)
3. Domain discovery service finds subdomains using Shodan API
4. For each domain (root + subdomains):
   - Resolves domain to IP address
   - Publishes finding to `domain_discovery_results` with `org_id`, `source="shodan"`, and `ip`
5. Domain ingestion consumer validates `source` is present (skips if missing)
6. For domain/subdomain findings:
   - Determines asset_type (domain vs subdomain) by dot count
   - Stores in `discoveries` collection with org_id, ownership_status="verified", and IP resolution history
   - Creates separate IP record in `discoveries` with org_id and parent_id
   - If domain IP changed: closes old resolution, adds new one to history
   - Triggers port scanning for new IPs

### Example: Port Discovery Service
```
internal/discoveries/port_discovery/
├── constants.go      # GroupPortDiscovery + CommonPorts array (23 ports)
├── service.go        # Uses shared.IPDiscoveryJob, publishes shared.IPDiscoveryFinding
├── consumer.go       # Listens to shared.StreamIPDiscoveryQueue with GroupPortDiscovery
└── services/
    └── port_scanner.go    # Simple TCP connect scanner with 2s timeout
```

**Port Discovery Flow:**
1. Job published to `ip_discovery_queue` (with `org_id`)
2. Port discovery service validates `org_id` is present (skips if missing)
3. Port discovery service scans 23 common ports (TCP connect, 2s timeout, concurrent)
4. For each open port:
   - Attempts to grab service banner (500ms timeout)
   - Publishes finding to `ip_discovery_results` with `org_id`, `source="port_discovery"`, port, protocol
5. Port ingestion consumer validates `source` is present (skips if missing)
6. For port findings:
   - Ensures IP record exists in `discoveries` (creates with org_id if not found)
   - Stores port in `discoveries` collection (asset_type: "port", with org_id, ownership_status="verified", parent_id: ip_id)
   - Tracks service changes: if ANY characteristic changes (service_name, product, version, or banner), archives complete old service state to previous_services array
   - If port exists: updates `last_seen`, merges metadata, and updates service fields
