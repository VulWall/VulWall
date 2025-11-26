# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Engine is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (discovery services, scanners) is implemented as an independent service that can be compiled and deployed separately, while sharing common infrastructure code.

**Key architectural principles:**
- Discovery services focus on finding assets and publish findings to Redis streams
- The **ingestion service** uses **vertical slice architecture** with concurrent consumers
- All jobs MUST include `org_id` (organization GUID) or they will be skipped
- **Two separate asset collections:**
  - `assets` - User-added assets to be scanned (managed via UI, enabled: true/false)
  - `discoveries` - Scan results/findings (auto-discovered, ownership_status: verified/notMine/notSure)
- **Org-scoped storage:** ALL assets stored with `org_id` (denormalized design)
- **Type discrimination:** Uses `asset_type` field (domain, subdomain, ip, port) for discoveries
- **Hierarchical relationships:** Domain → Subdomain → IP → Port via parent_id fields (org-scoped)
- **Two status fields:**
  - `asset.enabled` (true/false) - user-controlled via UI
  - `discovery.status` (active/inactive/unknown) - technical state
  - `discovery.ownership_status` (verified/notMine/notSure) - organizational state

## Project Structure

```
VulWall.NightWatch/
├── cmd/                    # Entry points for each service
│   ├── scan-coordinator/   # Scan coordinator entry point
│   │   └── main.go
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
│   │   ├── config/        # Configuration loader + env var constants
│   │   ├── logger/        # Zap logger setup
│   │   ├── mongox/        # MongoDB connection
│   │   └── redisx/        # Redis client & consumer groups
│   ├── shared/            # Cross-cutting concerns used by 2+ services
│   │   ├── models.go      # Shared models (DiscoveryJob, IPDiscoveryJob, Organization, Scan, etc.)
│   │   └── constants.go   # Shared constants (streams, protocols, statuses)
│   ├── scan_coordinator/  # Scan coordinator service (automatic scan scheduling)
│   │   ├── constants.go   # Scheduler interval configuration
│   │   ├── service.go     # Scan coordination logic
│   │   └── scheduler.go   # Periodic scheduler loop
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
       └─→ Sets metadata.geo.continent, metadata.geo.country, metadata.geo.isp (geolocation data)

INGESTION SERVICE ARCHITECTURE:
├─→ Orchestrator starts FOUR consumers concurrently
├─→ domain_ingestion: consumes domain_discovery_results
├─→ port_ingestion: consumes ip_discovery_results
├─→ findings_ingestion: consumes security_findings
└─→ enrichment_ingestion: consumes discovery_enrichment_results

SCAN COORDINATOR FLOW (AUTOMATED SCANNING):
1. Scan Coordinator runs on schedule (default: every hour)
   └─→ Queries organizations collection for orgs with scan_interval_days > 0

2. For each organization:
   ├─→ Check last scan from scans collection
   ├─→ Calculate days_since_last_scan = now - last_scan.created_at
   └─→ If days_since_last_scan >= org.subscription_settings.scan_interval_days:
       ├─→ Create new Scan record (status=pending, type=scheduled, triggered_by=system)
       ├─→ Query all enabled user-added assets for org from assets collection (enabled=true)
       └─→ Publish discovery jobs to Redis:
           ├─→ Domain assets → domain_discovery_queue (with scan_id + org_id)
           └─→ IP assets → ip_discovery_queue (with scan_id + org_id)

3. Discovery services process jobs normally
   └─→ All findings include scan_id for tracking which scan found them
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
  - `Asset` (user-added assets to be scanned: domain, ip)
  - `Discovery` (unified asset model for all 4 types with org_id: domain, subdomain, ip, port)
  - `ResolutionHistoryEntry` (IP resolution history for domains/subdomains)
  - `ServiceHistoryEntry` (service change history for ports)
- Scan coordination models:
  - `Organization`, `SubscriptionSettings` (org settings with scan_interval_days)
  - `Scan`, `ScanStats`, `AssetTarget` (scan execution tracking with targeted assets)
- Common data structures for inter-service communication

✅ **Put in `internal/shared/constants.go`:**
- Shared stream names:
  - `StreamDomainDiscoveryQueue`, `StreamDomainDiscoveryResults`
  - `StreamIPDiscoveryQueue`, `StreamIPDiscoveryResults`
  - `StreamSecurityFindings` - Security findings from scanners
  - `StreamDiscoveryEnrichmentResults` - Discovery enrichment data (WAF + IP geolocation)
- Shared collection names:
  - `CollectionAssets` - User-added assets to be scanned
  - `CollectionDiscoveries` - Org-scoped asset registry (includes org_id)
  - `CollectionFindings` - Security findings/vulnerabilities
  - `CollectionOrganizations` - Organizations with subscription settings
  - `CollectionScans` - Scan execution records
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
   - All assets include org_id, ownership_status (verified/notMine/notSure), and discovered_at timestamp

## Active Reconnaissance Scanner Architecture (Reference Pattern)

Active reconnaissance scanners perform security testing and vulnerability detection on discovered assets. The **js_dependency_scanner** serves as the **reference architecture** for all active recon scanners, demonstrating best practices for performance, maintainability, and clean code structure.

### Reference Implementation: js_dependency_scanner

**Location:** `internal/active_recon/js_dependency_scanner/`

**Purpose:** Detects JavaScript library vulnerabilities by:
1. Fetching HTML from target URLs (HTTP and HTTPS in parallel)
2. Extracting JavaScript file references
3. Downloading JS files in parallel (20 concurrent workers)
4. Running retire.js vulnerability scanner
5. Publishing security findings to Redis

**Performance Characteristics:**
- ✅ **4-5x faster** than sequential approach (15-20s vs 60-90s per domain)
- ✅ Parallel protocol scanning (HTTP + HTTPS concurrently)
- ✅ Parallel file downloads (20 worker pool)
- ✅ Retry logic with exponential backoff (3 retries: 1s, 2s, 4s)
- ✅ Optimized HTTP client with comprehensive timeouts
- ✅ Context-aware operations for graceful cancellation

### Architecture Pattern

**Directory Structure:**
```
internal/active_recon/js_dependency_scanner/
├── constants.go          # Consumer group name
├── models.go             # Scanner-specific models (ScanTarget)
├── service.go            # Orchestration layer (~200 lines)
│   ├── ProcessDiscovery()           # Main entry point
│   ├── scanBothProtocols()          # Parallel HTTP/HTTPS scanning
│   ├── publishUniqueVulnerabilities() # Deduplication & publishing
│   └── convertToSecurityFinding()   # Model conversion
├── consumer.go           # Redis consumer (dual-stream)
└── scanner/              # Scanner implementation package
    ├── scanner.go        # Scanner interface & implementation
    ├── html.go           # HTML fetching & JS extraction
    ├── downloader.go     # Parallel file downloader with retry
    └── retire.go         # retire.js executor & parser
```

**Key Principle:** **Separation of concerns**
- `service.go` - Orchestration only (coordinates scanning, handles findings)
- `scanner/` package - Pure scanning logic (no Redis, no MongoDB, fully testable)

### Core Patterns

#### 1. Scanner Interface Pattern

**Why:** Enables testing, mocking, and future scanner swapping

```go
// scanner/scanner.go
type Scanner interface {
    Scan(ctx context.Context, targetURL string) ([]ProcessedVulnerability, error)
}

type JSDependencyScanner struct {
    httpClient *http.Client
    logger     *zap.Logger
}

func NewScanner(logger *zap.Logger) *JSDependencyScanner {
    return &JSDependencyScanner{
        httpClient: CreateHTTPClient(),
        logger:     logger,
    }
}

func (s *JSDependencyScanner) Scan(ctx context.Context, targetURL string) ([]ProcessedVulnerability, error) {
    // 1. Fetch HTML
    htmlContent, err := FetchHTML(ctx, targetURL, s.httpClient, s.logger)

    // 2. Extract JS files
    jsFiles := ExtractJSFiles(htmlContent, targetURL, s.logger)

    // 3. Download files in parallel
    tmpDir, fileMetadata, err := DownloadFiles(ctx, jsFiles, s.httpClient, s.logger)
    defer os.RemoveAll(tmpDir)

    // 4. Run vulnerability scanner
    retireOutput, err := RunRetireJS(ctx, tmpDir, s.logger)

    // 5. Process results
    return ProcessVulnerabilities(retireOutput, fileMetadata, targetURL), nil
}
```

#### 2. Worker Pool Pattern (Parallel Operations)

**Why:** Dramatically improves performance for I/O-bound operations

**Use Case:** Downloading 20 JS files concurrently instead of sequentially (10-15s vs 200s)

```go
// scanner/downloader.go
func DownloadFiles(ctx context.Context, jsFiles []string, httpClient *http.Client, logger *zap.Logger) (string, []JSFileMetadata, error) {
    const numWorkers = 20

    // Create channels for job distribution
    jobs := make(chan downloadJob, len(jsFiles))
    results := make(chan downloadResult, len(jsFiles))

    // Start worker pool
    var wg sync.WaitGroup
    for w := 0; w < numWorkers; w++ {
        wg.Add(1)
        go downloadWorker(ctx, jobs, results, httpClient, logger, &wg)
    }

    // Distribute jobs
    for _, url := range jsFiles {
        jobs <- downloadJob{url: url, filePath: filepath.Join(tmpDir, filename)}
    }
    close(jobs)

    // Collect results
    go func() {
        wg.Wait()
        close(results)
    }()

    // Process results
    var fileMetadata []JSFileMetadata
    for result := range results {
        if result.err == nil {
            fileMetadata = append(fileMetadata, result.metadata)
        }
    }

    return tmpDir, fileMetadata, nil
}

func downloadWorker(ctx context.Context, jobs <-chan downloadJob, results chan<- downloadResult, httpClient *http.Client, logger *zap.Logger, wg *sync.WaitGroup) {
    defer wg.Done()

    for job := range jobs {
        select {
        case <-ctx.Done():
            return
        default:
            // Download with retry logic
            err := downloadFileWithRetry(ctx, job.url, job.filePath, httpClient, logger)
            results <- downloadResult{
                url:      job.url,
                filePath: job.filePath,
                err:      err,
                metadata: JSFileMetadata{URL: job.url, Filename: filepath.Base(job.filePath)},
            }
        }
    }
}
```

**Pattern Benefits:**
- ✅ Configurable concurrency (adjust `numWorkers` based on resource constraints)
- ✅ Graceful cancellation via context
- ✅ Channel-based communication (clean, idiomatic Go)
- ✅ WaitGroup for synchronization

#### 3. Retry Logic with Exponential Backoff

**Why:** Handles transient network failures gracefully

**Use Case:** Network timeouts, temporary server errors

```go
// scanner/downloader.go
func downloadFileWithRetry(ctx context.Context, url, filePath string, httpClient *http.Client, logger *zap.Logger) error {
    const maxRetries = 3
    var lastErr error

    for attempt := 0; attempt <= maxRetries; attempt++ {
        // Backoff delay: 0s, 1s, 2s, 4s
        if attempt > 0 {
            backoff := time.Duration(1<<(attempt-1)) * time.Second
            logger.Debug("Retrying download",
                zap.String("url", url),
                zap.Int("attempt", attempt),
                zap.Duration("backoff", backoff),
            )

            select {
            case <-time.After(backoff):
            case <-ctx.Done():
                return ctx.Err()
            }
        }

        err := downloadFile(ctx, url, filePath, httpClient)
        if err == nil {
            return nil // Success
        }

        lastErr = err

        // Don't retry non-retryable errors (404, 401, etc.)
        if !isRetryableError(err) {
            return err
        }
    }

    return fmt.Errorf("max retries exceeded: %w", lastErr)
}

func isRetryableError(err error) bool {
    // Retry on network errors, timeouts, 5xx status codes
    // Don't retry on 4xx client errors
    if err == nil {
        return false
    }

    errStr := err.Error()
    return strings.Contains(errStr, "timeout") ||
           strings.Contains(errStr, "connection refused") ||
           strings.Contains(errStr, "HTTP 5")
}
```

**Pattern Benefits:**
- ✅ Exponential backoff prevents overwhelming servers
- ✅ Context-aware (respects cancellation)
- ✅ Smart retry logic (skip permanent failures like 404)
- ✅ Detailed logging for debugging

#### 4. Parallel Protocol Scanning

**Why:** Scan both HTTP and HTTPS concurrently instead of sequentially (30s vs 60s)

```go
// service.go
func (s *Service) scanBothProtocols(ctx context.Context, target ScanTarget) []protocolScanResult {
    protocols := []string{"http", "https"}
    results := make(chan protocolScanResult, len(protocols))

    var wg sync.WaitGroup

    // Launch parallel scans
    for _, protocol := range protocols {
        wg.Add(1)
        go func(proto string) {
            defer wg.Done()

            url := fmt.Sprintf("%s://%s", proto, target.Target)
            vulnerabilities, err := s.scanner.Scan(ctx, url)

            if err != nil {
                s.logger.Debug("Failed to scan URL",
                    zap.String("url", url),
                    zap.Error(err),
                )
            }

            results <- protocolScanResult{
                protocol:        proto,
                url:             url,
                vulnerabilities: vulnerabilities,
            }
        }(protocol)
    }

    // Wait for completion
    go func() {
        wg.Wait()
        close(results)
    }()

    // Collect results
    var allResults []protocolScanResult
    for result := range results {
        if len(result.vulnerabilities) > 0 {
            allResults = append(allResults, result)
        }
    }

    return allResults
}
```

**Pattern Benefits:**
- ✅ Both protocols tested simultaneously
- ✅ Failures in one protocol don't block the other
- ✅ Clean result aggregation

#### 5. Optimized HTTP Client

**Why:** Prevent hangs on dead hosts, improve failure detection

```go
// scanner/html.go
func CreateHTTPClient() *http.Client {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // Allow self-signed certificates
        },
        ResponseHeaderTimeout: 10 * time.Second, // Detect hung servers quickly
        TLSHandshakeTimeout:   10 * time.Second, // TLS negotiation timeout
        MaxIdleConns:          100,
        MaxIdleConnsPerHost:   20,               // Increased for parallel downloads
        IdleConnTimeout:       30 * time.Second,
    }

    // Set dial timeout using custom dialer
    transport.DialContext = (&net.Dialer{
        Timeout: 5 * time.Second, // Fast DNS/TCP connection timeout
    }).DialContext

    return &http.Client{
        Timeout:   15 * time.Second, // Reduced from 30s for faster failure detection
        Transport: transport,
    }
}
```

**Timeout Strategy:**
- **DialTimeout (5s):** DNS resolution + TCP connection
- **TLSHandshakeTimeout (10s):** TLS negotiation
- **ResponseHeaderTimeout (10s):** Server must send headers within 10s
- **Overall Timeout (15s):** Total request timeout

**Pattern Benefits:**
- ✅ No 30+ second hangs on dead hosts
- ✅ Connection reuse for better performance
- ✅ TLS flexibility for self-signed certificates

#### 6. Deduplication Strategy

**Why:** Same vulnerability may be found in HTTP and HTTPS versions

```go
// service.go
func (s *Service) publishUniqueVulnerabilities(ctx context.Context, results []protocolScanResult, target ScanTarget) {
    // Dedup by component+version+CVE across all protocols
    seen := make(map[string]bool)

    for _, result := range results {
        for _, vuln := range result.vulnerabilities {
            // Create dedup key
            cveStr := strings.Join(vuln.CVEs, ",")
            if cveStr == "" {
                cveStr = "no-cve"
            }
            key := fmt.Sprintf("%s|%s|%s", vuln.Component, vuln.Version, cveStr)

            if !seen[key] {
                seen[key] = true

                // Convert to SecurityFinding and publish
                finding := convertToSecurityFinding(vuln, result.url, target)
                if err := s.publishFinding(ctx, finding); err != nil {
                    s.logger.Error("Failed to publish finding", zap.Error(err))
                    continue
                }

                s.logger.Info("Published vulnerability finding",
                    zap.String("component", vuln.Component),
                    zap.String("version", vuln.Version),
                    zap.String("severity", vuln.Severity),
                )
            }
        }
    }
}
```

### When to Use This Pattern

**✅ Use this pattern when:**
- Scanner performs I/O-bound operations (HTTP requests, file downloads)
- Multiple items can be processed in parallel (files, URLs, targets)
- Operation may encounter transient failures (network requests)
- Scanner needs to test multiple protocols/variants (HTTP/HTTPS)
- Code complexity justifies separation into package

**❌ Use simpler pattern when:**
- Scanner is CPU-bound (cryptographic operations)
- Sequential processing is acceptable (< 5 items)
- Operation is very simple (< 100 lines)
- No parallelization opportunities

### Implementation Checklist

When implementing a new active recon scanner using this pattern:

1. **Directory Structure:**
   - [ ] Create `internal/active_recon/[scanner_name]/` directory
   - [ ] Add `constants.go` (consumer group name)
   - [ ] Add `models.go` (scanner-specific models if needed)
   - [ ] Add `service.go` (orchestration layer)
   - [ ] Add `consumer.go` (Redis consumer)
   - [ ] Create `scanner/` subdirectory for implementation

2. **Scanner Package:**
   - [ ] Define `Scanner` interface in `scanner/scanner.go`
   - [ ] Implement scanner with clean, testable methods
   - [ ] Split complex operations into separate files (html.go, downloader.go, etc.)
   - [ ] Add retry logic for network operations
   - [ ] Use `shared.DefaultUserAgent` for HTTP requests
   - [ ] Implement optimized HTTP client with timeouts

3. **Orchestration Layer (service.go):**
   - [ ] Keep orchestration code under 200 lines
   - [ ] Implement deduplication logic if needed
   - [ ] Convert scanner results to `shared.SecurityFinding`
   - [ ] Publish findings to `shared.StreamSecurityFindings`
   - [ ] Set `Scanner` field to lowercase scanner name (e.g., "jsscanner")
   - [ ] Include proper error handling and logging

4. **Performance Optimization:**
   - [ ] Identify I/O-bound operations for parallelization
   - [ ] Implement worker pool pattern if processing multiple items (files, URLs)
   - [ ] Add parallel protocol scanning if applicable (HTTP/HTTPS)
   - [ ] Use context for cancellation support
   - [ ] Add retry logic with exponential backoff

5. **Consumer:**
   - [ ] Consume from appropriate stream(s) (domain_discovery_results, ip_discovery_results)
   - [ ] Validate required fields (org_id, scanner)
   - [ ] Handle both single and dual-stream consumption if needed
   - [ ] Implement proper error handling

6. **Testing:**
   - [ ] Unit tests for scanner package (no external dependencies)
   - [ ] Integration tests for service layer
   - [ ] Performance benchmarks if applicable

### Example: Applying Pattern to New Scanner

**Scenario:** Implementing a new "ssl_scanner" to detect TLS/SSL vulnerabilities

**Structure:**
```
internal/active_recon/ssl_scanner/
├── constants.go          # GroupSSLScanner = "ssl_scanner_service"
├── models.go             # SSLScanTarget
├── service.go            # Orchestration (~150 lines)
├── consumer.go           # Consumes domain_discovery_results
└── scanner/
    ├── scanner.go        # Scanner interface + SSLScanner implementation
    ├── protocols.go      # Parallel TLS version testing (TLS 1.0, 1.1, 1.2, 1.3)
    ├── ciphers.go        # Cipher suite enumeration with worker pool
    └── certificates.go   # Certificate chain validation
```

**Key Decisions:**
- ✅ Use worker pool for cipher suite enumeration (100+ ciphers to test)
- ✅ Parallel protocol testing (TLS 1.0-1.3 concurrently)
- ✅ Retry logic for network handshake failures
- ✅ Optimized TLS dialer with timeouts
- ✅ Dedup findings by (protocol + cipher + weakness type)

## Distributed Tracing (OpenTelemetry)

This project uses **OpenTelemetry** for distributed tracing with **W3C TraceContext propagation** across all services. This enables end-to-end visibility from scan initiation through discovery, scanning, and findings persistence.

### Tracing Infrastructure

**Location:** `internal/core/telemetry/`

- `telemetry.go` - OpenTelemetry initialization (Honeycomb OTLP exporter)
- `propagation.go` - W3C TraceContext injection/extraction utilities

**Configuration:**
- `OTEL_ENABLED` - Enable/disable tracing (default: enabled)
- `HONEYCOMB_API_KEY` - Honeycomb API key
- `OTEL_EXPORTER_OTLP_ENDPOINT` - OTLP endpoint (default: api.honeycomb.io)
- `OTEL_TRACES_SAMPLER` - Sampler strategy (default: parentbased_always_on)

### Trace Context Propagation Pattern

All services MUST follow this pattern to enable distributed tracing:

#### **1. Publishers: Inject Trace Context**

**When publishing to Redis streams, inject trace context BEFORE calling `PublishToStream`:**

```go
import "github.com/vulwall/scanners/internal/core/telemetry"

func (s *Service) publishFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
    // Inject trace context for span linking across service boundaries
    finding.TraceContext = telemetry.InjectTraceContext(ctx)

    return redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryResults, finding, 10000)
}
```

**Apply to:**
- Discovery services publishing findings (`DiscoveryFinding`, `IPDiscoveryFinding`)
- Ingestion services publishing jobs (`IPDiscoveryJob`, `EnrichmentJob`)
- Active recon scanners publishing findings (`SecurityFinding`, `EnrichmentFinding`)
- Scan coordinator publishing initial jobs (`DiscoveryJob`, `IPDiscoveryJob`)

#### **2. Consumers: Extract Trace Context**

**When consuming from Redis streams, extract trace context AFTER unmarshaling message:**

```go
import "github.com/vulwall/scanners/internal/core/telemetry"

func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
    var finding shared.DiscoveryFinding
    if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
        return fmt.Errorf("failed to unmarshal finding: %w", err)
    }

    // Extract trace context from message to link spans across service boundaries
    ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

    // Process with linked context
    if err := c.service.ProcessFinding(ctx, finding); err != nil {
        return fmt.Errorf("failed to process finding: %w", err)
    }

    return nil
}
```

**Apply to:**
- All consumer.go files in discovery services
- All consumer.go files in ingestion services
- All consumer.go files in active recon scanners

#### **3. Context Propagation in Goroutines**

**When spawning goroutines, pass the parent context to maintain trace links:**

```go
// ❌ WRONG: Breaks span hierarchy
go func() {
    s.discoverSubdomains(context.Background(), ...) // Lost context!
}()

// ✅ CORRECT: Maintains span hierarchy
go func() {
    s.discoverSubdomains(ctx, ...) // Preserves trace context
}()
```

### Trace Context in Shared Models

All stream-based models include a `TraceContext` field for W3C propagation:

```go
type DiscoveryJob struct {
    TraceID      string            `json:"trace_id" bson:"trace_id"`
    TraceContext map[string]string `json:"trace_context,omitempty" bson:"-"` // W3C headers
    // ... other fields
}
```

**Note:** The `bson:"-"` tag ensures trace context is **not stored in MongoDB** (only used for Redis streaming).

### End-to-End Trace Flow

```
Scan Coordinator (creates trace_id + root span)
    └─ Inject TraceContext → Publish DiscoveryJob
        └─ Domain Discovery Consumer (extract TraceContext)
            └─ Domain Discovery Service (create child span)
                └─ Inject TraceContext → Publish DiscoveryFinding
                    └─ Domain Ingestion Consumer (extract TraceContext)
                        └─ Domain Ingestion Service (create child span)
                            ├─ Inject TraceContext → Publish IPDiscoveryJob
                            │   └─ Port Discovery Consumer (extract TraceContext)
                            │       └─ Port Discovery Service (create child span)
                            │           └─ Inject TraceContext → Publish IPDiscoveryFinding
                            │               └─ Port Ingestion Consumer (extract TraceContext)
                            │                   └─ Port Ingestion Service (create child span)
                            └─ Inject TraceContext → Publish EnrichmentJob
                                └─ Enrichment Consumer (extract TraceContext)
                                    └─ Enrichment Service (create child span)
```

**Result:** Hierarchical waterfall in Honeycomb showing full causality chain with timing data.

### Adding Tracing to New Services

When creating a new service that publishes to or consumes from Redis streams:

1. **Publisher:**
   - Add import: `"github.com/vulwall/scanners/internal/core/telemetry"`
   - Before `PublishToStream`: `message.TraceContext = telemetry.InjectTraceContext(ctx)`

2. **Consumer:**
   - Add import: `"github.com/vulwall/scanners/internal/core/telemetry"`
   - After `json.Unmarshal`: `ctx = telemetry.ExtractTraceContext(ctx, message.TraceContext)`

3. **Service spans:**
   - Use `otel.Tracer("service-name")` to get tracer
   - Create spans: `ctx, span := tracer.Start(ctx, "operation_name")`
   - Add attributes: `span.SetAttributes(attribute.String("key", "value"))`
   - Always defer: `defer span.End()`

### Querying Traces in Honeycomb

```
# Find all spans for a scan
trace.trace_id = "abc-123-def-456"

# Find slow operations
duration_ms > 5000

# Find errors
error = true

# Group by service
VISUALIZE COUNT GROUP BY service.name
```

## Common Commands

### Building Services
```bash
make build                      # Build all services
make build-scan-coordinator     # Build scan-coordinator only
make build-domain-discovery     # Build domain-discovery only
make build-port-discovery       # Build port-discovery only
make build-nuclei-scanner       # Build nuclei-scanner only
make build-ingestion            # Build ingestion only
```

### Running Locally
```bash
make run-scan-coordinator       # Run scan-coordinator service
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
       "github.com/redis/go-redis/v9"
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
   - **Type: "geolocation"** → Sets `metadata.geo.continent`, `metadata.geo.country`, `metadata.geo.isp`
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
    geo: {                        // ← IP geolocation (nested)
      continent: "North America",
      country: "United States",
      isp: "Cloudflare, Inc."
    }
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
  "metadata.geo.country": "United States"
})
```

**Find assets by ISP:**
```javascript
db.discoveries.find({
  org_id: "org-456",
  "metadata.geo.isp": /cloudflare/i  // Case-insensitive regex match
})
```

**Find assets by continent:**
```javascript
db.discoveries.find({
  org_id: "org-456",
  "metadata.geo.continent": "North America"
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

## Scan Coordinator (Automated Scanning)

The Scan Coordinator is a background service that **automatically schedules and triggers scans** based on organization subscription settings.

### Overview

**Location:** `internal/scan_coordinator/`

**Purpose:** Automates recurring scans for organizations based on their subscription plans, eliminating the need for manual scan initiation.

**Key Features:**
- ✅ Runs on a schedule (default: every hour)
- ✅ Queries organizations with `scan_interval_days > 0`
- ✅ Checks time since last scan
- ✅ Creates scan records and publishes discovery jobs automatically
- ✅ Only scans **enabled user-added assets** from `assets` collection (`enabled = true`)
- ✅ Tracks all scans in `scans` collection for auditing

### Architecture

**Components:**
- `constants.go` - Scheduler interval configuration (default: 3600 seconds)
- `scheduler.go` - Periodic scheduler loop that runs coordination cycles
- `service.go` - Core coordination logic (check org settings, trigger scans)

**How It Works:**

1. **Scheduler Loop:** Runs every N seconds (configurable)
2. **Query Organizations:** Finds orgs with `subscription_settings.scan_interval_days > 0`
3. **For Each Organization:**
   - Retrieve last scan from `scans` collection
   - Calculate `days_since_last_scan = (now - last_scan.created_at) / 24h`
   - If `days_since_last_scan >= scan_interval_days`:
     - Create new `Scan` record (status=pending, type=scheduled, triggered_by=system)
     - Query all enabled user-added assets for org from `assets` collection (`enabled = true`)
     - Publish discovery jobs to Redis streams (with `scan_id` + `org_id`)

### Data Models

**Asset Model** (in `shared/models.go`):**
```go
// Asset represents a user-added asset to be scanned
// Stored in assets collection (user-managed assets, not scan discoveries)
// Matches VulWall.Dashboard.Data.Entities.Asset.Asset entity
type Asset struct {
    ID            string     // MongoDB ObjectId
    OrgID         string     // Organization GUID
    Type          string     // "domain" or "ip"
    Enabled       bool       // true = enabled, false = disabled
    DNSVerifiedAt *time.Time // DNS verification timestamp
    Domain        *string    // For domain assets
    IP            *string    // For IP assets
    AddedOn       time.Time  // When asset was added
}
```

**Organization Model** (in `shared/models.go`):
```go
type Organization struct {
    ID                   string               // Organization UUID
    UserIDs              []string             // Associated users
    CompanyName          string
    Industry             string
    Website              string
    CertVisible          bool
    CreatedAt            time.Time
    UpdatedAt            time.Time
    SubscriptionSettings SubscriptionSettings // Scan configuration
}

type SubscriptionSettings struct {
    ScanIntervalDays int // How often to scan (0 = disabled)
    MaxAssets        int // Maximum allowed assets
}
```

**Scan Model** (in `shared/models.go`):
```go
type Scan struct {
    ID             string        // Scan UUID
    OrgID          string        // Organization GUID
    Status         string        // "pending", "running", "completed", "failed"
    Type           string        // "manual", "scheduled", "on_demand"
    TriggeredBy    string        // User ID or "system"
    StartedAt      *time.Time
    CompletedAt    *time.Time
    CreatedAt      time.Time
    UpdatedAt      time.Time
    TargetedAssets []AssetTarget // Assets that were targeted for scanning (audit trail)
    Stats          ScanStats     // Scan statistics
}

type AssetTarget struct {
    AssetID string // References assets._id
    Type    string // "domain" or "ip"
    Value   string // Domain name or IP address
}

type ScanStats struct {
    TotalAssets      int // Total assets to scan
    AssetsScanned    int // Assets scanned so far
    NewAssets        int // New assets discovered
    FindingsDetected int // Security findings found
}
```

### Database Collections

**Assets Collection:**
```javascript
{
  _id: ObjectId("..."),
  org_id: "507f1f77bcf86cd799439011",
  type: "domain",              // "domain" or "ip"
  enabled: true,               // true = enabled, false = disabled
  dns_verified_at: ISODate("2025-11-09T08:53:38.744Z"),
  domain: "moj.dev",          // For domain assets
  // ip: "8.8.8.8",           // For IP assets
  added_on: ISODate("2025-11-09T08:53:27.775Z")
}
```

**Organizations Collection:**
```javascript
{
  _id: "org-uuid-123",
  user_ids: ["user-1", "user-2"],
  company_name: "Example Corp",
  industry: "Technology",
  website: "https://example.com",
  cert_visible: true,
  created_at: ISODate("2025-01-01"),
  updated_at: ISODate("2025-01-10"),
  subscription_settings: {
    scan_interval_days: 7,  // Scan every 7 days
    max_assets: 1000
  }
}
```

**Scans Collection:**
```javascript
{
  _id: "scan-uuid-456",
  org_id: "org-uuid-123",
  status: "running",           // pending → running → completed/failed
  type: "scheduled",           // scheduled (auto), manual (UI), on_demand
  triggered_by: "system",      // "system" for automated scans
  started_at: null,
  completed_at: null,
  created_at: ISODate("2025-01-10T12:00:00Z"),
  updated_at: ISODate("2025-01-10T12:00:00Z"),
  targeted_assets: [           // Assets that were targeted for scanning (audit trail)
    {
      asset_id: "asset-uuid-1",
      type: "domain",
      value: "example.com"
    },
    {
      asset_id: "asset-uuid-2",
      type: "ip",
      value: "192.168.1.100"
    }
  ],
  stats: {
    total_assets: 2,           // Count of targeted_assets
    assets_scanned: 0,
    new_assets: 0,
    findings_detected: 0
  }
}
```

### Integration with Discovery Services

The Scan Coordinator seamlessly integrates with existing discovery services:

1. **Publishes Standard Jobs:** Uses `shared.DiscoveryJob` and `shared.IPDiscoveryJob`
2. **Includes scan_id:** All jobs include the scan UUID for tracking
3. **No Changes to Discovery Services:** Discovery services work unchanged
4. **Scan Tracking:** All discoveries and findings include `scan_ids` array

**Example Flow:**
```
Scan Coordinator (every hour)
    ↓
Check: Last scan was 8 days ago, scan_interval_days = 7
    ↓
1. Create Scan (scan_id = "scan-abc-456")
2. Query enabled user-added assets from assets collection (enabled = true)
3. Publish jobs:
   ├─→ domain_discovery_queue: {org_id, scan_id, host: "moj.dev"}        (from asset.domain)
   ├─→ domain_discovery_queue: {org_id, scan_id, host: "api.moj.dev"}   (from asset.domain)
   └─→ ip_discovery_queue: {org_id, scan_id, ip: "192.168.1.100"}       (from asset.ip)
    ↓
Discovery Services Process Jobs
    ↓
Findings stored in discoveries collection (scan results) with scan_id = "scan-abc-456"
    ↓
Query discoveries by scan: db.discoveries.find({scan_ids: "scan-abc-456"})
```

### Configuration

**Scheduler Interval:** Configured in `internal/scan_coordinator/constants.go`
```go
const SchedulerInterval = 3600 // 1 hour in seconds
```

To change the interval, modify this constant and rebuild.

### Deployment

**Build:**
```bash
make build-scan-coordinator
```

**Run Locally:**
```bash
make run-scan-coordinator
```

**Deploy to Production:**
```bash
make prod-deploy-scan-coordinator           # Deploy
make prod-stop-service SERVICE=scan-coordinator  # Stop
make prod-logs SERVICE=scan-coordinator OPTS=-f  # View logs
```

**Deploy All Services (includes scan-coordinator):**
```bash
make prod-deploy-all
```

### Disabling Automated Scans

To disable automated scans for an organization:
```javascript
db.organizations.updateOne(
  { _id: "org-uuid" },
  { $set: { "subscription_settings.scan_interval_days": 0 } }
)
```

To re-enable:
```javascript
db.organizations.updateOne(
  { _id: "org-uuid" },
  { $set: { "subscription_settings.scan_interval_days": 7 } }
)
```

### Monitoring Scans

**View all scans for an organization:**
```javascript
db.scans.find({ org_id: "org-uuid" }).sort({ created_at: -1 })
```

**Check last scan:**
```javascript
db.scans.findOne(
  { org_id: "org-uuid" },
  { sort: { created_at: -1 } }
)
```

**Query discoveries from a specific scan:**
```javascript
db.discoveries.find({
  org_id: "org-uuid",
  scan_ids: "scan-abc-456"
})
```

**Count assets discovered per scan:**
```javascript
db.discoveries.aggregate([
  { $match: { org_id: "org-uuid", scan_ids: "scan-abc-456" } },
  { $group: { _id: "$asset_type", count: { $sum: 1 } } }
])
```

**Get assets that were targeted/scanned (for UI display):**
```javascript
// Get scan with targeted assets
const scan = db.scans.findOne({ _id: "scan-abc-456" })

// Count of assets scanned
const count = scan.targeted_assets.length

// Names/values of assets scanned
const assetNames = scan.targeted_assets.map(a => a.value)
// Returns: ["example.com", "192.168.1.100"]

// Get full asset details with types
scan.targeted_assets.forEach(target => {
  console.log(`${target.type}: ${target.value}`)
})
// Output:
// domain: example.com
// ip: 192.168.1.100
```

**Compare targeted vs discovered assets:**
```javascript
// Get what we planned to scan
const scan = db.scans.findOne({ _id: "scan-abc-456" })
const targetedCount = scan.targeted_assets.length

// Get what we actually discovered
const discoveredCount = db.discoveries.countDocuments({
  org_id: scan.org_id,
  scan_ids: "scan-abc-456"
})

console.log(`Targeted: ${targetedCount}, Discovered: ${discoveredCount}`)
```

### Important Notes

- ✅ **Only ONE instance** should run (do not scale horizontally)
- ✅ **Minimal resource usage** - only queries MongoDB and publishes to Redis
- ✅ **Two collections:**
  - `assets` - User-added assets to be scanned (enabled: true / false)
  - `discoveries` - Scan results/findings (ownership_status: "verified" / "notMine" / "notSure")
- ✅ **Only scans enabled user-added assets** - queries from `assets` collection with `enabled = true`
- ✅ **Audit trail** - All scans logged with `triggered_by = "system"`
- ✅ **Graceful shutdown** - Handles SIGTERM/SIGINT properly
- ✅ **See [SCAN_COORDINATOR.md](SCAN_COORDINATOR.md)** for complete documentation

## Key Files

### Infrastructure (`internal/core/`)
- `bootstrap/bootstrap.go` - Common service initialization pattern (eliminates boilerplate)
- `config/config.go` - Environment-based configuration loader
- `config/env.go` - Centralized environment variable name constants (single source of truth)
- `logger/logger.go` - Zap logger initialization
- `redisx/client.go` - Redis client with consumer group helpers
- `mongox/client.go` - MongoDB connection manager
- `telemetry/telemetry.go` - OpenTelemetry initialization and tracing setup
- `telemetry/propagation.go` - W3C TraceContext injection/extraction utilities

### Bootstrap Pattern Architecture

The project uses a **bootstrap pattern** to eliminate boilerplate code and ensure consistent service initialization. All services use one of two bootstrap variants depending on their requirements.

#### Bootstrap Variants

**1. `bootstrap.Run()` - Full Bootstrap (Single-Stream with MongoDB)**

For services that:

- Consume from a single Redis stream
- Require MongoDB access
- Need automatic consumer group management

**Example:** js-dependency-scanner

```go
package main

import (
    "github.com/vulwall/scanners/internal/active_recon/js_dependency_scanner"
    "github.com/vulwall/scanners/internal/core/bootstrap"
    "github.com/vulwall/scanners/internal/shared"
)

func main() {
    bootstrap.Run(bootstrap.ServiceConfig{
        ServiceName:   "js-dependency-scanner",
        StreamName:    shared.StreamDomainDiscoveryResults,
        ConsumerGroup: js_dependency_scanner.GroupJSDependencyScanner,
        Factory: func(cfg *config.Config, redisClient *redis.Client, mongoDB *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
            return js_dependency_scanner.NewConsumer(redisClient, mongoDB, logger)
        },
    })
}
```

**What it provides:**

- ✅ Configuration loading from environment
- ✅ Structured logging initialization (Zap)
- ✅ OpenTelemetry tracing initialization (automatic)
- ✅ Redis client connection
- ✅ MongoDB connection
- ✅ Consumer group creation (automatic)
- ✅ Graceful shutdown handling (SIGTERM/SIGINT)
- ✅ Error handling and panic recovery

**2. `bootstrap.RunSimple()` - Simple Bootstrap (No MongoDB)**

For services that do NOT need MongoDB access. Supports two modes:

**Mode A: Single-stream with automatic consumer group creation**
- Specify `Streams` field with stream/group pairs
- Bootstrap creates consumer groups automatically

**Example:** domain-discovery, port-discovery

```go
func main() {
    bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
        ServiceName: "domain-discovery",
        Streams: []bootstrap.StreamConfig{
            {StreamName: shared.StreamDomainDiscoveryQueue, ConsumerGroup: domain_discovery.GroupShodanSubdomainService},
        },
        Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
            return domain_discovery.NewConsumer(redisClient, shodanAPIKey, logger), nil
        },
    })
}
```

**Mode B: Multi-stream (service handles consumer groups)**
- Leave `Streams` empty
- Service creates consumer groups in its `Start()` method

**Example:** nuclei-scanner, testssl-scanner, webtechprofiler, discovery-enrichment

```go
func main() {
    bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
        ServiceName: "nuclei-scanner",
        Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
            return nuclei_scanner.NewConsumer(redisClient, logger), nil
        },
    })
}
```

**What it provides:**

- ✅ Configuration loading from environment
- ✅ Structured logging initialization (Zap)
- ✅ **OpenTelemetry tracing initialization (automatic)**
- ✅ Redis client connection
- ✅ Consumer group creation (if `Streams` specified)
- ❌ No MongoDB connection (not needed)
- ✅ Graceful shutdown handling (SIGTERM/SIGINT)
- ✅ Error handling and panic recovery

#### Bootstrap Refactoring (2025)

**Problem:** Four active reconnaissance scanners (Nuclei, TestSSL, WebTechProfiler, Discovery Enrichment) were using manual initialization code instead of the bootstrap pattern. This resulted in:

- ❌ ~230 lines of duplicate initialization code across 4 services
- ❌ Each main.go file was ~75-80 lines (mostly boilerplate)
- ❌ **Missing OpenTelemetry initialization** - spans were created but silently dropped (no TracerProvider)
- ❌ Inconsistent architecture (js-dependency-scanner used bootstrap, others didn't)

**Solution:** Extended bootstrap pattern with `RunSimple()` variant and migrated all 4 scanners.

**Results:**

- ✅ Eliminated ~230 lines of duplicate code (76% reduction)
- ✅ Reduced each main.go from ~75 lines to 18 lines
- ✅ Automatic OpenTelemetry initialization now guaranteed
- ✅ All active recon scanners now use consistent architecture
- ✅ Honeycomb traces now show spans for all scanners

**Before (75 lines - manual initialization):**
```go
package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/redis/go-redis/v9"
    "github.com/vulwall/scanners/internal/active_recon/nuclei_scanner"
    "github.com/vulwall/scanners/internal/core/config"
    "github.com/vulwall/scanners/internal/core/logger"
    "github.com/vulwall/scanners/internal/core/redisx"
    "github.com/vulwall/scanners/internal/core/telemetry"
    "go.uber.org/zap"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        panic(err)
    }

    // Initialize logger
    log, err := logger.New(cfg.ServiceName, cfg.Environment)
    if err != nil {
        panic(err)
    }
    defer log.Sync()

    // Initialize OpenTelemetry
    ctx := context.Background()
    tracerProvider, err := telemetry.InitTracing(ctx, cfg.ServiceName, cfg.Environment, log)
    if err != nil {
        log.Fatal("Failed to initialize tracing", zap.Error(err))
    }
    defer func() {
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
            log.Error("Failed to shutdown tracer provider", zap.Error(err))
        }
    }()

    // Connect to Redis
    redisClient := redisx.NewClient(&redis.Options{
        Addr:     cfg.Redis.Addr,
        Password: cfg.Redis.Password,
        DB:       cfg.Redis.DB,
    })
    defer redisClient.Close()

    // Create consumer
    consumer := nuclei_scanner.NewConsumer(redisClient, log)

    // Start consumer
    consumerCtx, cancel := context.WithCancel(ctx)
    defer cancel()

    go func() {
        if err := consumer.Start(consumerCtx); err != nil {
            log.Fatal("Consumer failed", zap.Error(err))
        }
    }()

    // Wait for shutdown signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
    <-sigChan

    log.Info("Shutting down gracefully...")
    cancel()
    time.Sleep(2 * time.Second)
}
```

**After (18 lines - bootstrap pattern):**
```go
package main

import (
    "github.com/redis/go-redis/v9"
    "github.com/vulwall/scanners/internal/active_recon/nuclei_scanner"
    "github.com/vulwall/scanners/internal/core/bootstrap"
    "github.com/vulwall/scanners/internal/core/config"
    "go.uber.org/zap"
)

func main() {
    bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
        ServiceName: "nuclei-scanner",
        Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
            return nuclei_scanner.NewConsumer(redisClient, logger), nil
        },
    })
}
```

**Impact:** This refactoring resolved a critical production issue where active recon scanner spans were missing from Honeycomb traces. Data was being stored in MongoDB, but without proper OpenTelemetry initialization, all spans were silently discarded. The bootstrap pattern now guarantees that OpenTelemetry is initialized before any service logic runs.

#### When to Use Each Bootstrap Variant

**Use `bootstrap.Run()` when:**

- Service consumes from a **single Redis stream**
- Service needs **MongoDB access**
- Service uses standard single-stream consumer pattern
- Example: js-dependency-scanner

**Use `bootstrap.RunSimple()` when:**

- Service does **NOT need MongoDB**
- Single-stream with `Streams` config: domain-discovery, port-discovery
- Multi-stream (handles own consumer groups): nuclei-scanner, testssl-scanner, webtechprofiler, discovery-enrichment

**Use neither (manual initialization) when:**

- Service has highly custom initialization requirements
- Service doesn't follow standard consumer patterns
- Examples: scan-coordinator (scheduler, not consumer), ingestion orchestrator (multi-consumer orchestration)

#### Adding Bootstrap to New Services

When creating a new service, **always prefer using a bootstrap variant** instead of manual initialization:

1. **Determine which variant to use** (see "When to Use" above)
2. **Create minimal main.go** with appropriate bootstrap call
3. **Implement consumer interface** that bootstrap expects
4. **Deploy** - OpenTelemetry and all infrastructure automatically initialized

### Shared Package (`internal/shared/`)
- `models.go` - Models used by 2+ services:
  - Job formats: `DiscoveryJob`, `IPDiscoveryJob`
  - Finding formats: `DiscoveryFinding`, `IPDiscoveryFinding`, `SecurityFinding`, `EnrichmentFinding`
  - Asset models:
    - `Asset` (user-added assets to be scanned: domain, ip)
    - `Discovery` (unified model for all 4 scan result types: domain, subdomain, ip, port)
  - Organization models: `Organization`, `SubscriptionSettings`
  - Scan models: `Scan`, `ScanStats`
  - History models: `ResolutionHistoryEntry`, `ServiceHistoryEntry`
- `constants.go` - Constants used by 2+ services (streams, collections, asset types, protocols, statuses, scan types)

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
    DiscoveredAt   time.Time // When asset was discovered
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
- `shared.CollectionAssets = "assets"` - User-added assets to be scanned (includes org_id)
- `shared.CollectionDiscoveries = "discoveries"` - Org-scoped scan results registry (all 4 asset types, includes org_id)
- `shared.CollectionFindings = "findings"` - Security findings/vulnerabilities
- `shared.CollectionOrganizations = "organizations"` - Organizations with subscription settings
- `shared.CollectionScans = "scans"` - Scan execution records

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
}).sort({ discovered_at: -1 })

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

- `github.com/redis/go-redis/v9` - Redis client with Streams support
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
- **Use bootstrap pattern** - All services use `bootstrap.Run()` or `bootstrap.RunSimple()` to eliminate boilerplate and ensure OpenTelemetry initialization

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
