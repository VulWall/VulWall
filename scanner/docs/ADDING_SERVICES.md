# Adding Services

## Pre-flight Checklist

Before merging any new service, verify ALL of the following:

- [ ] Consumer group constant defined in `[service]/constants.go`
- [ ] Stream names use constants from `src/internal/shared/constants.go`
- [ ] `org_id` validated — skip jobs/findings without it
- [ ] `source` field set on all published findings
- [ ] TraceContext injected before publishing (see [OBSERVABILITY.md](OBSERVABILITY.md))
- [ ] TraceContext extracted after consuming (see [OBSERVABILITY.md](OBSERVABILITY.md))
- [ ] **Scan monitor updated** — add consumer group to `isComplete()` in `src/internal/scan_coordinator/scan_monitor.go`
- [ ] **Stream cleanup updated** — add new result streams to `streamsToClean()` in `src/internal/scan_coordinator/stream_cleanup.go`
- [ ] **SERVICE_REGISTRY.md updated** — add service to all relevant tables
- [ ] Entry point created in `src/cmd/`
- [ ] Makefile targets added (build, run, docker-scale, prod-deploy)
- [ ] Dockerfile created in `ops/`
- [ ] docker-compose.yml created in service's `ops/` directory
- [ ] **CI/CD: Added to `.github/workflows/docker-build-push.yml`** build matrix
- [ ] **Deploy: Added to `ops/scripts/deploy-all.sh`** SERVICES array
- [ ] **Deploy: Added to `ops/scripts/deploy-service.sh`** routing condition + help text

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

### 4. Create entry point

```go
// src/cmd/discoveries/[service-name]/main.go
func main() {
    bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
        ServiceName: "[service-name]",
        Streams: []bootstrap.StreamConfig{
            {StreamName: shared.StreamDomainDiscoveryQueue, ConsumerGroup: [pkg].Group[ServiceName]},
        },
        Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
            return [pkg].NewConsumer(redisClient, logger), nil
        },
    })
}
```

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

**Single-stream (most scanners):**
```go
// Consumes only from domain_scan_triggers
bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
    ServiceName: "[scanner-name]",
    Factory: func(...) (bootstrap.ConsumerStarter, error) {
        return [pkg].NewConsumer(redisClient, logger), nil
    },
})
```
Service handles consumer group creation internally using `CreateConsumerGroupFromLatest`.

**Dual-stream (nuclei, testssl):**
Consumer creates groups on both `domain_scan_triggers` and `port_scan_triggers`.

### 5. Consumer group start position

- **Trigger streams** (`domain_scan_triggers`, `port_scan_triggers`): use `CreateConsumerGroupFromLatest` (from `$`) — only process new discoveries
- **Result streams** (`ip_discovery_results` for webtechprofiler): use `CreateConsumerGroup` (from `0`) — guaranteed delivery

### 6. Implementation checklist

- [ ] Scanner interface in `scanner/` package
- [ ] Service orchestration under 200 lines
- [ ] Convert results to `shared.SecurityFinding`
- [ ] Set `Source` to a consistent lowercase name (existing: "nuclei", "testssl", "jsscanner", "http-headers", "webtechprofiler")
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

## Bootstrap Reference

### Decision Matrix

| Condition | Bootstrap | Example |
|-----------|-----------|---------|
| Single stream + MongoDB | `bootstrap.Run()` | js-dependency-scanner |
| Single stream + no MongoDB | `bootstrap.RunSimple()` with `Streams` | domain-discovery, port-discovery |
| Multi-stream + no MongoDB | `bootstrap.RunSimple()` without `Streams` | nuclei-scanner, testssl-scanner |
| Custom init (scheduler, orchestrator) | Manual | scan-coordinator, ingestion |

### bootstrap.Run() — Single-stream with MongoDB

```go
func main() {
    bootstrap.Run(bootstrap.ServiceConfig{
        ServiceName:   "my-service",
        StreamName:    shared.StreamDomainDiscoveryResults,
        ConsumerGroup: my_pkg.GroupMyService,
        Factory: func(cfg *config.Config, redisClient *redis.Client, mongoDB *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
            return my_pkg.NewConsumer(redisClient, mongoDB, logger)
        },
    })
}
```

### bootstrap.RunSimple() — No MongoDB

**Mode A: Single-stream (bootstrap creates consumer group):**
```go
func main() {
    bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
        ServiceName: "my-service",
        Streams: []bootstrap.StreamConfig{
            {StreamName: shared.StreamDomainDiscoveryQueue, ConsumerGroup: my_pkg.GroupMyService},
        },
        Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
            return my_pkg.NewConsumer(redisClient, logger), nil
        },
    })
}
```

**Mode B: Multi-stream (service handles own consumer groups):**

Services listed as "RunSimple (manual)" in SERVICE_REGISTRY.md use this mode. The service creates its own consumer groups inside `consumer.go`'s `Start()` method. Use when:
- Service consumes from multiple streams (nuclei, testssl)
- Different start positions per stream (webtechprofiler: `$` on triggers, `0` on results)

```go
func main() {
    bootstrap.RunSimple(bootstrap.SimpleServiceConfig{
        ServiceName: "my-scanner",
        Factory: func(cfg *config.Config, redisClient *redis.Client, logger *zap.Logger) (bootstrap.ConsumerStarter, error) {
            return my_pkg.NewConsumer(redisClient, logger), nil
        },
    })
}
```

### What bootstrap provides

| Feature | Run() | RunSimple() |
|---------|-------|-------------|
| Config loading | Yes | Yes |
| Zap logger | Yes | Yes |
| OpenTelemetry | Yes | Yes |
| Redis client | Yes | Yes |
| MongoDB | Yes | No |
| Consumer group creation | Yes | If `Streams` specified |
| Graceful shutdown | Yes | Yes |
