# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

VulWall NightWatch is a **vertically-sliced Go monorepo** for security scanning. Each service compiles and deploys independently while sharing common infrastructure.

**Core rules:**
- All jobs MUST include `org_id` (organization GUID) or they will be skipped
- Discovery services publish to Redis streams — **NO MongoDB access**
- The **ingestion service** is the ONLY service that writes to MongoDB
- Two asset collections: `assets` (user-added, UI-managed) and `discoveries` (scan results)
- Type discrimination via `asset_type` field: domain, subdomain, ip, port
- Parent-child hierarchy (org-scoped): domain → subdomain → IP → port via `parent_id`

## Project Structure

```
VulWall.NightWatch/
├── CLAUDE.md              ← You are here
├── docs/                  ← Detailed documentation (see index below)
├── Makefile
├── README.md
├── ops/                   # Docker, compose, deploy scripts
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
    │   │   ├── webtechprofiler/
    │   │   ├── js-dependency-scanner/
    │   │   ├── http-header-scanner/
    │   │   └── discovery-enrichment/
    │   ├── enrichers/
    │   │   └── ai-finding-enricher/
    │   └── ingestion/
    ├── internal/
    │   ├── core/            # bootstrap, config, logger, mongox, redisx, telemetry, shodan
    │   ├── shared/          # models.go, constants.go (cross-service)
    │   ├── scan_coordinator/
    │   ├── discoveries/     # domain_discovery, port_discovery
    │   ├── active_recon/    # nuclei, testssl, webtechprofiler, js_dep, http_header, discovery_enrichment
    │   ├── enrichers/       # ai_finding_enricher
    │   └── ingestion/       # orchestrator + 6 slices (domain, port, findings, enrichment, ai_enrichment, audit)
    ├── go.mod
    └── go.sum
```

## Documentation Index

| Document | Purpose |
|----------|---------|
| **[docs/SERVICE_REGISTRY.md](docs/SERVICE_REGISTRY.md)** | All 16 services, Redis streams, consumer groups, scan monitor coverage — **the ground truth** |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Communication flows, design patterns, model ownership rules |
| **[docs/DATABASE.md](docs/DATABASE.md)** | Go models, MongoDB schemas, query examples |
| **[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md)** | OpenTelemetry tracing patterns, Honeycomb queries |
| **[docs/ADDING_SERVICES.md](docs/ADDING_SERVICES.md)** | Step-by-step guides: new discovery service, scanner, enrichment, ingestion slice |
| **[ops/PRODUCTION.md](ops/PRODUCTION.md)** | Production deployment guide |

## Common Commands

### Building
```bash
make build                      # Build all services
make build-scan-coordinator     # Build single service
make build-domain-discovery
make build-port-discovery
make build-nuclei-scanner
make build-ingestion
make build-ai-finding-enricher
```

### Running Locally
```bash
make run-scan-coordinator
make run-domain-discovery
make run-port-discovery
make run-nuclei-scanner
make run-ingestion              # Runs all 6 ingestion slices
make run-ai-finding-enricher
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

> **Why this matters:** Missing step 3 causes scans to complete before the new scanner finishes. This is the scan_monitor bug class.

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
| `ai_enrichment_queue` | job |
| `ai_enrichment_results` | result |
| `system_audit_logs` | audit |

### MongoDB Collections
| Collection | Purpose |
|------------|---------|
| `assets` | User-added assets (UI-managed) |
| `discoveries` | Scan results (4 asset types, org-scoped) |
| `findings` | Security vulnerabilities |
| `organizations` | Org settings with scan_cron |
| `scans` | Scan execution records |
| `audit_logs` | System audit events |

### Key Constants Location
- Stream/collection names: `src/internal/shared/constants.go`
- Consumer groups: each service's `constants.go`
- Scan monitor tracking: `src/internal/scan_coordinator/scan_monitor.go:105-127`
- Stream cleanup: `src/internal/scan_coordinator/stream_cleanup.go:30-38`

## Configuration

Environment variables (`.env`):

| Variable | Purpose |
|----------|---------|
| `REDIS_URI` | Cloud Redis connection string |
| `MONGO_URI` | MongoDB Atlas connection string |
| `MONGO_DB` | Database name (default: vulwall) |
| `SHODAN_API_KEY` | Shodan API key for discovery |
| `GROQ_API_KEY` | Groq API key for AI enrichment |
| `ENVIRONMENT` | development / production |
| `HONEYCOMB_API_KEY` | Honeycomb API key for tracing |

See `.env.example` for full list.

## Dependencies

- `github.com/redis/go-redis/v9` — Redis client with Streams
- `go.mongodb.org/mongo-driver` — MongoDB driver
- `go.uber.org/zap` — Structured logging
- `github.com/robfig/cron/v3` — Cron scheduler
- `github.com/joho/godotenv` — Env variable management
- `github.com/google/uuid` — UUID generation
- `go.opentelemetry.io/otel` — OpenTelemetry SDK
