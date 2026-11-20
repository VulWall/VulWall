# Adding Services

## Pre-flight Checklist

Before merging any new service, verify ALL of the following:

- [ ] Consumer group constant defined in `[service]/constants.go`
- [ ] Stream names use constants from `src/internal/shared/constants.go`
- [ ] `org_id` validated — skip jobs/findings without it
- [ ] `source` field set on all published findings
- [ ] TraceContext injected before publishing (see [OBSERVABILITY.md](OBSERVABILITY.md))
- [ ] TraceContext extracted after consuming (see [OBSERVABILITY.md](OBSERVABILITY.md))
- [ ] **Scan monitor updated** — add the (stream, group) pair to `scanPipelineGroups()` in `src/internal/scan_coordinator/pipeline.go` and to `TestScanPipelineGroups`
- [ ] **Stream cleanup updated** — add new result streams to `streamsToClean()` in `src/internal/scan_coordinator/stream_cleanup.go`
- [ ] **SERVICE_REGISTRY.md updated** — add service to all relevant tables
- [ ] Component registered in `src/cmd/nightwatch/main.go` (and its group in `createConsumerGroups()` for job queues and trigger streams) — see [Wiring a Component](#wiring-a-component-into-nightwatch)
- [ ] External tools (if any) installed and pinned in `scanner/Dockerfile`

---

## Adding a Discovery Service

Discovery services find assets and publish findings. They have **NO MongoDB access**.

### 1. Create service directory

```
src/internal/discoveries/[service_name]/
├── constants.go   # Consumer group name
├── service.go     # Discovery logic, publishes findings
├── consumer.go    # Redis consumer
└── [tool]/        # Optional: tool-specific implementation
    └── client.go
```

### 2. Define consumer group

```go
// constants.go
package [service_name]

const (
    Group[ServiceName] = "[service_name]_service"
    ConsumerBatchSize  = 1
)
```

### 3. Implement service

```go
// service.go — NO MongoDB dependency
func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
    // 1. Validate org_id
    // 2. Run discovery logic
    // 3. For each finding:
    finding.TraceContext = telemetry.InjectTraceContext(ctx)
    return redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryResults, finding, 10000)
}
```

### 4. Register it in `nightwatch`

Add the consumer to `consumers()` and its job-queue group (from `0`) to
`createConsumerGroups()` in `src/cmd/nightwatch/main.go`. See
[Wiring a Component](#wiring-a-component-into-nightwatch).

### 5. Update scan monitor & registry

Add consumer group to `isComplete()` and update [SERVICE_REGISTRY.md](SERVICE_REGISTRY.md).

**Key rules:**
- Use `shared.StreamDomainDiscoveryQueue` (input) and `shared.StreamDomainDiscoveryResults` (output)
- Use unique consumer group per tool
- Use `shared.DiscoveryJob` for input, `shared.DiscoveryFinding` for output
- Set `source` field (e.g., "nmap", "masscan")

---

## Adding an Active Recon Scanner

Active recon scanners perform security testing on discovered assets. Reference implementations: `js_dependency_scanner`, `http_header_scanner`.

### 1. Create directory structure

```
src/internal/active_recon/[scanner_name]/
├── constants.go      # Consumer group name
├── models.go         # Scanner-specific models (optional)
├── service.go        # Orchestration (~200 lines max)
├── consumer.go       # Redis consumer
└── scanner/          # Pure scanning logic (no Redis/MongoDB)
    ├── scanner.go    # Scanner interface + implementation
    └── [files].go    # Split by responsibility
```

### 2. Implement Scanner interface

```go
// scanner/scanner.go
type Scanner interface {
    Scan(ctx context.Context, targetURL string) ([]Vulnerability, error)
}
```

Keep scanning logic in `scanner/` package — no Redis, no MongoDB, fully testable.

### 3. Implement service orchestration

```go
// service.go — coordinates scanning, publishes findings
func (s *Service) ProcessDiscovery(ctx context.Context, target ScanTarget) error {
    // 1. Call scanner
    vulns, err := s.scanner.Scan(ctx, target.URL)
    // 2. Deduplicate if needed
    // 3. Convert to shared.SecurityFinding
    // 4. Publish to shared.StreamSecurityFindings with source + TraceContext
}
```

### 4. Choose consumer pattern

**Single-stream (most scanners):** consume only from `domain_scan_triggers`.
The consumer creates its group in `Start()` with `CreateConsumerGroupFromLatest`;
also add the group to `createConsumerGroups()` in `src/cmd/nightwatch/main.go`
and register the consumer in `consumers()`.

**Dual-stream (nuclei):**
Consumer creates groups on both `domain_scan_triggers` and `port_scan_triggers`.

### 5. Consumer group start position

- **Trigger streams** (`domain_scan_triggers`, `port_scan_triggers`): use `CreateConsumerGroupFromLatest` (from `$`) — only process new discoveries
- **Result streams** (e.g. `ip_discovery_results`): use `CreateConsumerGroup` (from `0`) — guaranteed delivery

### 6. Implementation checklist

- [ ] Scanner interface in `scanner/` package
- [ ] Service orchestration under 200 lines
- [ ] Convert results to `shared.SecurityFinding`
- [ ] Set `Source` to a consistent lowercase name (existing: "nuclei", "testssl", "jsscanner", "http-headers")
- [ ] Publish to `shared.StreamSecurityFindings`
- [ ] Inject TraceContext before publishing
- [ ] Extract TraceContext after consuming
- [ ] Add to scan monitor's `isComplete()` (critical!)
- [ ] Add to SERVICE_REGISTRY.md

### Performance patterns (use when applicable)

- **Worker pool:** For I/O-bound parallel operations (file downloads, HTTP requests)
- **Parallel protocol scanning:** Test HTTP and HTTPS concurrently
- **Retry with exponential backoff:** For transient network failures
- **Optimized HTTP client:** Custom timeouts to prevent hangs on dead hosts

---

## Adding an Enrichment Type

Two options for adding new enrichment (e.g., CDN detection, tech stack profiling):

### Option 1: Extend existing discovery_enrichment service

1. Add enrichment method to `service.go` (e.g., `enrichCDN()`)
2. Call from `ProcessEnrichment()` based on `asset_type`
3. Publish `EnrichmentFinding` with your `enrichment_type`
4. Add case in `enrichment_ingestion/service.go`:
   ```go
   case "cdn":
       return s.processCDNEnrichment(ctx, enrichment)
   ```

### Option 2: Create separate enrichment service

1. Follow `discovery_enrichment` pattern in `src/internal/active_recon/`
2. Consume from `discovery_enrichment_queue`
3. Filter by `asset_type` if needed
4. Publish `EnrichmentFinding` with your `enrichment_type`
5. Add case in `enrichment_ingestion/service.go`

**Storage guidelines:**
- Use simple types: string, number, boolean, or simple nested objects
- Avoid arrays or complex history tracking
- Store in `metadata.*` (e.g., `metadata.cdn = "Cloudflare"`, `metadata.cms = "WordPress"`)

---

## Adding an Ingestion Slice

The ingestion orchestrator runs multiple consumer slices concurrently.

### 1. Create slice directory

```
src/internal/ingestion/[slice_name]/
├── constants.go   # Consumer group name
├── service.go     # MongoDB persistence logic
└── consumer.go    # Redis consumer
```

### 2. Define consumer group

```go
const GroupNewIngestion = "new_ingestion_service"
```

### 3. Register in orchestrator

Add the new consumer to `src/internal/ingestion/orchestrator.go`:

```go
// In startConsumers() or equivalent
newConsumer := new_ingestion.NewConsumer(redisClient, mongoDB, logger)
go newConsumer.Start(ctx)
```

### 4. Update SERVICE_REGISTRY.md

Add the new slice to the service inventory and stream tables.

---

## Wiring a Component into `nightwatch`

Every component runs inside the single `nightwatch` process
(`src/cmd/nightwatch/main.go`). There is no per-service entry point, Dockerfile
or compose file. To add a component:

1. **Constructor.** Give the consumer a `NewConsumer(...)` and a
   `Start(ctx context.Context) error` that blocks until `ctx` is cancelled.
   Return errors; never call `os.Exit` or `logger.Fatal` — one failing
   component must not kill the process without a clean shutdown.
2. **Register it** in `consumers()` (stream consumers) or
   `coordinatorComponents()` (coordinator goroutines):

   ```go
   myScanner, err := my_scanner.NewConsumer(rdb, named("my-scanner"))
   if err != nil {
       return nil, fmt.Errorf("my-scanner: %w", err)
   }
   list = append(list, component{"my-scanner", myScanner.Start})
   ```
3. **Consumer groups.** A consumer of a job queue or a trigger stream also gets
   an entry in `createConsumerGroups()`, so the group exists before the scan
   coordinator can publish to that stream. Job queues start at `0`
   (`CreateConsumerGroup`), trigger streams at `$`
   (`CreateConsumerGroupFromLatest`). Keep the call inside the consumer's
   `Start()` too (it is idempotent), so the consumer works on its own in tests.
4. **Configuration.** Read service-specific settings with `config.GetEnv*`
   and constants in `src/internal/core/config/env.go`. Add new variables to
   the root `.env.example` and `docker-compose.yml` when users should set them.
5. **External tools.** If the component runs a CLI tool, install a pinned,
   checksum-verified version in `scanner/Dockerfile`. The image runs as a
   non-root user; write only to `$HOME`, the temp dir or `/data/*` volumes.

### What `main.go` provides

| Feature | Notes |
|---------|-------|
| Config loading | `config.Load()` (reads `.env` when present) |
| Zap logger | one logger; each component gets a `component` field |
| OpenTelemetry | `telemetry.InitTracing()` once; opt-in via `OTEL_ENABLED` |
| Redis client | one shared `*redis.Client` |
| MongoDB | one shared `*mongo.Database`; only ingestion and the scan coordinator write |
| Indexes | `mongox.EnsureIndexes()` before any component starts |
| Graceful shutdown | SIGINT/SIGTERM cancel the shared context; `main` waits for every component |
