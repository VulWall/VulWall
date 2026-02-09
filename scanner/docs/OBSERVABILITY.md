# Observability

## Tracing Infrastructure

**Location:** `src/internal/core/telemetry/`

| File | Purpose |
|------|---------|
| `telemetry.go` | OpenTelemetry initialization (Honeycomb OTLP exporter) |
| `propagation.go` | W3C TraceContext injection/extraction utilities |

**Environment variables:**

| Variable | Purpose | Default |
|----------|---------|---------|
| `OTEL_ENABLED` | Enable/disable tracing | enabled |
| `HONEYCOMB_API_KEY` | Honeycomb API key | — |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint | `api.honeycomb.io` |
| `OTEL_TRACES_SAMPLER` | Sampler strategy | `parentbased_always_on` |

**Note:** The bootstrap pattern (`Run`/`RunSimple`) automatically initializes OpenTelemetry. Services using manual initialization must call `telemetry.InitTracing()` explicitly.

---

## Trace Context Propagation

All services MUST follow this pattern for distributed tracing across Redis streams.

### 1. Publishers: Inject Trace Context

**Before calling `PublishToStream`, inject trace context:**

```go
import "github.com/vulwall/scanners/internal/core/telemetry"

func (s *Service) publishFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
    finding.TraceContext = telemetry.InjectTraceContext(ctx)
    return redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryResults, finding, 10000)
}
```

**Apply to all publishers:** discovery services, ingestion services, active recon scanners, scan coordinator.

### 2. Consumers: Extract Trace Context

**After unmarshaling a message, extract trace context:**

```go
import "github.com/vulwall/scanners/internal/core/telemetry"

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

**Result:** Hierarchical waterfall in Honeycomb showing full causality chain with timing data.

---

## Adding Tracing to New Services

### 1. Publisher
```go
import "github.com/vulwall/scanners/internal/core/telemetry"

// Before PublishToStream:
message.TraceContext = telemetry.InjectTraceContext(ctx)
```

### 2. Consumer
```go
import "github.com/vulwall/scanners/internal/core/telemetry"

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

## Querying Traces in Honeycomb

```
# All spans for a scan
trace.trace_id = "abc-123-def-456"

# Slow operations
duration_ms > 5000

# Errors
error = true

# Group by service
VISUALIZE COUNT GROUP BY service.name
```

---

## Logging

**Library:** `go.uber.org/zap` (structured logging)

**Location:** `src/internal/core/logger/`

All services use structured logging initialized via bootstrap. Log levels and format vary by `ENVIRONMENT`:
- `development` — human-readable console output
- `production` — JSON structured output
