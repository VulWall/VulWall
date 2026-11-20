# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.


## Project Overview

The VulWall scanner (formerly NightWatch) is a **vertically-sliced Go monorepo** for security scanning. Each service compiles and deploys independently while sharing common infrastructure.

**Core rules:**
- All jobs MUST include `org_id` (organization GUID) or they will be skipped
- Discovery services publish to Redis streams — **NO MongoDB access**
- The **ingestion service** is the ONLY service that writes to MongoDB
- Two asset collections: `assets` (user-added, UI-managed) and `discoveries` (scan results)
- Type discrimination via `asset_type` field: domain, subdomain, ip, port
- Parent-child hierarchy (org-scoped): domain → subdomain → IP → port via `parent_id`

## Project Structure

```
scanner/
├── CLAUDE.md              ← You are here
├── docs/                  ← Detailed documentation (see index below)
├── Makefile
├── README.md
├── ops/                   # Dockerfiles, per-service compose files
│   └── docker-compose.yml
└── src/                   # Go source code
    ├── cmd/
    │   ├── scan-coordinator/
    │   ├── discoveries/
    │   │   ├── domain-discovery/
    │   │   └── port-discovery/
    │   ├── active_recon/
    │   │   ├── nuclei-scanner/
    │   │   ├── testssl-scanner/
    │   │   ├── js-dependency-scanner/
    │   │   ├── http-header-scanner/
    │   │   ├── email-security-scanner/
    │   │   └── discovery-enrichment/
    │   ├── enrichers/
    │   │   └── knowledge-base-engine/
    │   └── ingestion/
    ├── internal/
    │   ├── core/            # bootstrap, config, logger, mongox, redisx, telemetry, subfinderx
    │   ├── shared/          # models.go, constants.go (cross-service)
    │   ├── scan_coordinator/
    │   ├── discoveries/     # domain_discovery, port_discovery
    │   ├── active_recon/    # nuclei, testssl, js_dep, http_header, email_security, discovery_enrichment
    │   ├── enrichers/       # knowledge_base (Anthropic Claude KB engine)
    │   └── ingestion/       # orchestrator + 6 slices (domain, port, findings, enrichment, kb, audit)
    ├── go.mod
    └── go.sum
```

## Documentation Index

| Document | Purpose |
|----------|---------|
| **[docs/SERVICE_REGISTRY.md](docs/SERVICE_REGISTRY.md)** | All 16 services, Redis streams, consumer groups, scan monitor coverage — **the ground truth** |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Communication flows, design patterns, model ownership rules |
| **[docs/DATABASE.md](docs/DATABASE.md)** | Go models, MongoDB schemas, query examples |
| **[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md)** | OpenTelemetry tracing patterns |
| **[docs/ADDING_SERVICES.md](docs/ADDING_SERVICES.md)** | Step-by-step guides: new discovery service, scanner, enrichment, ingestion slice |

## Common Commands

### Building
```bash
make build                      # Build all services
make build-scan-coordinator     # Build single service
make build-domain-discovery
make build-port-discovery
make build-nuclei-scanner
make build-ingestion
make build-knowledge-base-engine
make build-email-security-scanner
```

### Running Locally
```bash
make run-scan-coordinator
make run-domain-discovery
make run-port-discovery
make run-nuclei-scanner
make run-ingestion              # Runs all 6 ingestion slices (domain, port, findings, enrichment, kb, audit)
make run-knowledge-base-engine
make run-email-security-scanner
```

### Docker Operations
```bash
make docker-up                         # Start all
make docker-down                       # Stop all
make docker-scale-domain-discovery N=2
make docker-scale-nuclei-scanner N=3
make docker-logs
```

### Testing & Code Quality
```bash
make test                   # Run all tests
make test-coverage          # With coverage report
make fmt                    # Format code
make lint                   # Run linter
make vet                    # Run go vet
make deps                   # Download and tidy dependencies
```

## Critical Rules

### When Adding a New Scanner or Service

1. Define consumer group in `[service]/constants.go`
2. Use stream constants from `src/internal/shared/constants.go`
3. **Update scan monitor** — add consumer group to `isComplete()` in `src/internal/scan_coordinator/scan_monitor.go`
4. **Update stream cleanup** — add new result streams to `streamsToClean()` in `src/internal/scan_coordinator/stream_cleanup.go`
5. **Update SERVICE_REGISTRY.md** — add to all relevant tables
6. Inject TraceContext before publishing, extract after consuming
7. Add Makefile targets, Dockerfile, docker-compose entry

> **Why this matters:** Missing step 3 causes scans to complete before the new scanner finishes.

### Architecture Invariants

- Discovery services: **NO MongoDB access** — publish to Redis only
- Ingestion service: **ONLY writer to MongoDB** — single source of truth
- All jobs require `org_id` — consumers MUST validate and skip if missing
- All findings require `source` — ingestion MUST validate and skip if missing
- Use `bootstrap.Run()` or `bootstrap.RunSimple()` — never manual init (ensures OpenTelemetry)
- Trigger streams use `CreateConsumerGroupFromLatest` (from `$`) — ephemeral
- Result/job streams use `CreateConsumerGroup` (from `0`) — guaranteed delivery

### Data Rules

- Findings deduplicated by `(org_id, discovery_id, finding_type, title)`
- `scan_ids` uses `$addToSet` — never overwrite
- Two status fields: `status` (technical) vs `ownership_status` (organizational)
- Enrichment stores in `metadata.*` (e.g., `metadata.waf`, `metadata.geo.*`)

## Quick Reference

### Redis Streams
| Stream | Category |
|--------|----------|
| `domain_discovery_queue` | job |
| `domain_discovery_results` | result |
| `ip_discovery_queue` | job |
| `ip_discovery_results` | result |
| `domain_scan_triggers` | trigger |
| `port_scan_triggers` | trigger |
| `security_findings` | result |
| `discovery_enrichment_queue` | job |
| `discovery_enrichment_results` | result |
| `kb_generation_queue` | job |
| `kb_generation_results` | result |
| `system_audit_logs` | audit |

### MongoDB Collections
| Collection | Purpose |
|------------|---------|
| `assets` | User-added assets (UI-managed) |
| `discoveries` | Scan results (4 asset types, org-scoped) |
| `findings` | Security vulnerabilities |
| `knowledge_base` | Shared KB entries by finding_type (~84 entries) |
| `organizations` | Org settings with scan_cron |
| `scans` | Scan execution records |
| `audit_logs` | System audit events |

### Key Constants Location
- Stream/collection names: `src/internal/shared/constants.go`
- Consumer groups: each service's `constants.go`
- Scan monitor tracking: `src/internal/scan_coordinator/scan_monitor.go:105-131`
- Stream cleanup: `src/internal/scan_coordinator/stream_cleanup.go:30-38`

## Configuration

Environment variables (`.env`):

| Variable | Purpose |
|----------|---------|
| `REDIS_URI` | Redis connection string |
| `MONGO_URI` | MongoDB connection string |
| `MONGO_DB` | Database name (default: vulwall) |
| `ANTHROPIC_API_KEY` | Anthropic API key for KB generation |
| `ANTHROPIC_MODEL` | Anthropic model (default: claude-sonnet-4-5-20250514) |
| `ENVIRONMENT` | development / production |
| `HONEYCOMB_API_KEY` | Optional key sent as the `x-honeycomb-team` header to the OTLP trace exporter |
| `NUCLEI_INCLUDE_TAGS` | Nuclei template include tags (default: cve,vuln,exposure,...; empty = no filter) |
| `NUCLEI_EXCLUDE_TAGS` | Nuclei template exclude tags (default: intrusive,dos,fuzz; empty = no filter) |
| `NIGHTWATCH_API_KEY` | Bearer key callers must send in `X-API-Key` to access `POST /api/scans`. Empty = auth disabled (dev only) |
| `DASHBOARD_WEBHOOK_URL` | Dashboard webhook endpoint for scan-completion notifications (empty = disabled) |
| `DASHBOARD_WEBHOOK_SECRET` | HMAC-SHA256 signing secret. Sent as `X-Webhook-Signature: sha256={hex}`. Must match Dashboard's `NIGHTWATCH_WEBHOOK_SECRET` |

See `.env.example` for full list.

## Dependencies

- `github.com/redis/go-redis/v9` — Redis client with Streams
- `go.mongodb.org/mongo-driver` — MongoDB driver
- `go.uber.org/zap` — Structured logging
- `github.com/robfig/cron/v3` — Cron scheduler
- `github.com/joho/godotenv` — Env variable management
- `github.com/google/uuid` — UUID generation
- `go.opentelemetry.io/otel` — OpenTelemetry SDK
