# Observability

## Tracing Infrastructure

Tracing is **optional and off by default**. Without it the scanner only writes
logs to the console (`docker compose logs scanner`). When enabled, the scanner
exports OpenTelemetry traces over OTLP/HTTP to any compatible backend: Jaeger,
Grafana Tempo, an OpenTelemetry Collector, or a hosted vendor.

**Location:** `src/internal/core/telemetry/`

| File | Purpose |
|------|---------|
| `telemetry.go` | OpenTelemetry initialization (OTLP/HTTP exporter, sampler, resource) |
| `propagation.go` | W3C TraceContext injection/extraction utilities |

The `nightwatch` binary calls `telemetry.InitTracing()` once at startup. If the
exporter cannot be created, the scanner logs a warning and runs without traces.

**Environment variables** (standard OpenTelemetry names):

| Variable | Purpose | Default |
|----------|---------|---------|
| `OTEL_ENABLED` | Turn tracing on (`true`) | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP base URL; `/v1/traces` is appended | `http://localhost:4318` |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Full traces URL (overrides the base URL) | — |
| `OTEL_EXPORTER_OTLP_HEADERS` | Extra headers, e.g. an API key: `key1=value1,key2=value2` | — |
| `OTEL_SERVICE_NAME` | `service.name` resource attribute | `vulwall-scanner` |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes | — |
| `OTEL_TRACES_SAMPLER` | `always_on`, `always_off`, `probabilistic`, `parentbased_always_on`, `parentbased_probabilistic` | `parentbased_always_on` |
| `OTEL_TRACES_SAMPLER_ARG` | Ratio for the probabilistic samplers | `0.1` |
| `OTEL_BSP_*` | Batch span processor tuning | SDK defaults |

### Example: Jaeger with Docker Compose

The root `docker-compose.yml` has a `tracing` profile with Jaeger all-in-one.
Set this in `.env`:

```bash
OTEL_ENABLED=true
```

and start with the profile:

```bash
docker compose --profile tracing up -d
```

The compose file points the scanner at `http://jaeger:4318`. Open the Jaeger
UI at http://localhost:16686 and select the `vulwall-scanner` service.

### Example: a hosted OTLP backend

```bash
OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.example.com
OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <token>
```

---

## Trace Context Propagation

All services MUST follow this pattern for distributed tracing across Redis streams.

### 1. Publishers: Inject Trace Context

**Before calling `PublishToStream`, inject trace context:**

```go
import "github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"

func (s *Service) publishFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
    finding.TraceContext = telemetry.InjectTraceContext(ctx)
    return redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryResults, finding, 10000)
}
```

**Apply to all publishers:** discovery services, ingestion services, active recon scanners, scan coordinator.

### 2. Consumers: Extract Trace Context

**After unmarshaling a message, extract trace context:**

```go
import "github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"

func (c *Consumer) handleMessage(ctx context.Context, message redis.XMessage) error {
    var finding shared.DiscoveryFinding
    if err := json.Unmarshal([]byte(dataStr), &finding); err != nil {
        return fmt.Errorf("failed to unmarshal finding: %w", err)
    }

    ctx = telemetry.ExtractTraceContext(ctx, finding.TraceContext)

    if err := c.service.ProcessFinding(ctx, finding); err != nil {
        return fmt.Errorf("failed to process finding: %w", err)
    }
    return nil
}
```

**Apply to all `consumer.go` files** in discovery, ingestion, and active recon services.

### 3. Context Propagation in Goroutines

```go
// WRONG: Breaks span hierarchy
go func() {
    s.discoverSubdomains(context.Background(), ...)
}()

// CORRECT: Maintains span hierarchy
go func() {
    s.discoverSubdomains(ctx, ...)
}()
```

---

## Trace Context in Models

All stream-based models include a `TraceContext` field for W3C propagation:

```go
type DiscoveryJob struct {
    TraceID      string            `json:"trace_id" bson:"trace_id"`
    TraceContext map[string]string `json:"trace_context,omitempty" bson:"-"`
    // ... other fields
}
```

**Critical:** The `bson:"-"` tag ensures trace context is **not stored in MongoDB** — it's only used for Redis stream propagation.

---

## End-to-End Trace Flow

```
Scan Coordinator (root span, creates trace_id)
    └─ Inject → Publish DiscoveryJob
        └─ Domain Discovery Consumer (extract)
            └─ Domain Discovery Service (child span)
                └─ Inject → Publish DiscoveryFinding
                    └─ Domain Ingestion Consumer (extract)
                        └─ Domain Ingestion Service (child span)
                            ├─ Inject → Publish IPDiscoveryJob
                            │   └─ Port Discovery Consumer (extract)
                            │       └─ Port Discovery Service (child span)
                            │           └─ Inject → Publish IPDiscoveryFinding
                            │               └─ Port Ingestion Consumer (extract)
                            │                   └─ Port Ingestion Service (child span)
                            ├─ Inject → Publish to domain_scan_triggers
                            │   └─ Nuclei/TestSSL/etc. (extract)
                            │       └─ Publish SecurityFinding
                            │           └─ Findings Ingestion (extract)
                            └─ Inject → Publish to discovery_enrichment_queue
                                └─ Discovery Enrichment (extract)
                                    └─ Enrichment Ingestion (extract)
```

**Result:** A hierarchical waterfall in your tracing UI that shows the full causality chain with timing data.

---

## Adding Tracing to New Services

### 1. Publisher
```go
import "github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"

// Before PublishToStream:
message.TraceContext = telemetry.InjectTraceContext(ctx)
```

### 2. Consumer
```go
import "github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"

// After json.Unmarshal:
ctx = telemetry.ExtractTraceContext(ctx, message.TraceContext)
```

### 3. Service Spans
```go
tracer := otel.Tracer("service-name")
ctx, span := tracer.Start(ctx, "operation_name")
defer span.End()
span.SetAttributes(attribute.String("key", "value"))
```

---

## Useful Span Attributes

Search on these in the tracing UI:

| Attribute | Example |
|-----------|---------|
| `scan.id` | all spans of one scan |
| `org.id` | all work for one organization |
| `discovery.id` | all work on one discovered asset |
| `target` | one scanned host or URL |

---

## Logging

**Library:** `go.uber.org/zap` (structured logging)

**Location:** `src/internal/core/logger/`

The `nightwatch` binary initializes one zap logger at startup. Log levels and format vary by `ENVIRONMENT`:
- `development` — human-readable console output
- `production` — JSON structured output
