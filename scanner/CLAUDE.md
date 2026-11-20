# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.


## Project Overview

The VulWall scanner (formerly NightWatch) is a **vertically-sliced Go monorepo** for security scanning. All components (scan coordinator, discovery, active-recon scanners, enrichment, KB engine, ingestion) run as goroutines in **one binary**, `nightwatch` (`src/cmd/nightwatch/main.go`), and talk to each other only through Redis streams. The scanner ships as one container image (`scanner/Dockerfile`) and runs from the repo-root `docker-compose.yml`.

**Core rules:**
- All jobs MUST include `org_id` (organization GUID) or they will be skipped
- Discovery services publish to Redis streams — **NO MongoDB access**
- The **ingestion service** is the ONLY writer of scan data (`discoveries`, `findings`, `knowledge_base`, `audit_logs`); the scan coordinator writes only `scans`
- The web app and the scanner share **no HTTP API**: the web app inserts a `scans` doc with `status: "queued"`, the coordinator claims it and the web app polls it for `done`/`failed`
- Two asset collections: `assets` (user-added, UI-managed) and `discoveries` (scan results)
- Type discrimination via `asset_type` field: domain, subdomain, ip, port
- Parent-child hierarchy (org-scoped): domain → subdomain → IP → port via `parent_id`

## Project Structure

```
scanner/
├── CLAUDE.md              ← You are here
├── Dockerfile             # The one scanner image (nuclei, testssl.sh, retire.js)
├── docker/entrypoint.sh   # Downloads DB-IP Lite geo DBs, then execs nightwatch
├── docs/                  ← Detailed documentation (see index below)
├── Makefile
├── README.md
└── src/                   # Go source code
    ├── cmd/
    │   └── nightwatch/      # The single binary: wires and supervises every component
    ├── internal/
    │   ├── core/            # config, logger, mongox, redisx, telemetry, subfinderx, audit
    │   ├── shared/          # models.go, constants.go (cross-component)
    │   ├── scan_coordinator/  # scheduler, queued-scan poller, scan monitor, stream cleanup
    │   ├── discoveries/     # domain_discovery, port_discovery
    │   ├── active_recon/    # nuclei, testssl, js_dep, http_header, email_security, discovery_enrichment
    │   ├── enrichers/       # knowledge_base (optional Anthropic Claude KB engine)
    │   └── ingestion/       # orchestrator + 6 slices (domain, port, findings, enrichment, kb, audit)
    ├── go.mod
    └── go.sum
```

## Documentation Index

| Document | Purpose |
|----------|---------|
| **[docs/SERVICE_REGISTRY.md](docs/SERVICE_REGISTRY.md)** | All 16 components, Redis streams, consumer groups, scan monitor coverage — **the ground truth** |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Communication flows, design patterns, model ownership rules |
| **[docs/DATABASE.md](docs/DATABASE.md)** | Go models, MongoDB schemas, scan lifecycle, finding text fields |
| **[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md)** | Optional OpenTelemetry tracing (any OTLP backend), logging |
| **[docs/ADDING_SERVICES.md](docs/ADDING_SERVICES.md)** | Step-by-step guides: new discovery service, scanner, enrichment, ingestion slice; wiring into `nightwatch` |

## Common Commands

```bash
make build          # Build src/bin/nightwatch
make run            # Run locally (needs Redis + MongoDB; nuclei, testssl.sh, retire on PATH)
make test           # Run all tests
make test-coverage  # With coverage report
make fmt            # Format code
make lint           # Run linter
make vet            # Run go vet
make deps           # Download and tidy dependencies

make docker-build   # Build the scanner image (root docker-compose.yml)
make docker-up      # Start mongo, redis, scanner and web
make docker-down    # Stop the stack
make docker-logs    # Follow scanner logs
```

`nightwatch healthcheck` pings Redis and MongoDB and exits 0/1 (used by the
container health check; the scanner opens no port).

## Critical Rules

### When Adding a New Scanner or Service

1. Define consumer group in `[service]/constants.go`
2. Use stream constants from `src/internal/shared/constants.go`
3. **Update scan monitor** — add the (stream, group) pair to `scanPipelineGroups()` in `src/internal/scan_coordinator/pipeline.go`, after the stages that feed it (guarded by `TestScanPipelineGroups`); only the enrichment and KB streams stay out
4. **Update stream cleanup** — add new result streams to `streamsToClean()` in `src/internal/scan_coordinator/stream_cleanup.go`
5. **Update SERVICE_REGISTRY.md** — add to all relevant tables
6. Inject TraceContext before publishing, extract after consuming
7. **Register in `src/cmd/nightwatch/main.go`** — add the consumer to `consumers()` and its job-queue/trigger group to `createConsumerGroups()`; install any CLI tool (pinned, checksum-verified) in `scanner/Dockerfile`

> **Why this matters:** Missing step 3 causes scans to complete before the new scanner finishes.

### Architecture Invariants

- Discovery services: **NO MongoDB access** — publish to Redis only
- Ingestion service: **ONLY writer of scan data in MongoDB** — single source of truth (the coordinator writes only `scans`)
- All jobs require `org_id` — consumers MUST validate and skip if missing
- All findings require `source` — ingestion MUST validate and skip if missing
- Components get Redis/Mongo/logger from `main.go`; return errors from `Start()` — never `os.Exit` or `logger.Fatal` inside a component
- Trigger streams use `CreateConsumerGroupFromLatest` (from `$`) — ephemeral
- Result/job streams use `CreateConsumerGroup` (from `0`) — guaranteed delivery
- `redisx.ConsumeStream` ACKs after the handler returns, also on handler error and on a recovered panic (logged with stack). A handler that fails because shutdown cancelled its context is NOT ACKed
- At startup `nightwatch` closes every `pending`/`running` scan as `failed` with `status_reason: "interrupted_by_restart"` (no finding resolution), then deletes the previous process's consumers (and their pending entries) from the `scanPipelineGroups()` groups (`ReleaseOrphanedPending`), before any component starts

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
| `knowledge_base` | Shared KB entries by finding_type (only when the KB engine runs) |
| `organizations` | Org settings with scan_cron |
| `scans` | Scan execution records (web app inserts `queued`; coordinator claims) |
| `audit_logs` | System audit events |

### Key Constants Location
- Stream/collection names: `src/internal/shared/constants.go`
- Consumer groups: each service's `constants.go`
- Scan monitor tracking: `src/internal/scan_coordinator/pipeline.go` — `scanPipelineGroups()`
- Stream cleanup: `src/internal/scan_coordinator/stream_cleanup.go` — `streamsToClean()`
- Component wiring: `src/cmd/nightwatch/main.go`

## Configuration

Environment variables (the repo-root `.env.example` lists the ones users set):

| Variable | Purpose |
|----------|---------|
| `REDIS_URI` | Redis connection string (default `redis://localhost:6379/0`) |
| `MONGO_URI` | MongoDB connection string (default `mongodb://localhost:27017`) |
| `MONGO_DB` | Database name (default: `vulwall`) |
| `ANTHROPIC_API_KEY` | Optional. Enables the KB engine; unset = KB stage skipped |
| `ANTHROPIC_MODEL` | Anthropic model for the KB engine (default: `claude-sonnet-4-6`) |
| `ENVIRONMENT` | `development` (console logs) / `production` (JSON logs; the image default) |
| `NUCLEI_WORKERS` | Concurrent nuclei processes across both trigger streams (default 2) |
| `NUCLEI_TEMPLATES_DIR` | nuclei templates directory (default `$HOME/nuclei-templates`; image: `/data/nuclei-templates`) |
| `NUCLEI_INCLUDE_TAGS` | Nuclei template include tags (default: cve,vuln,exposure,...; empty = no filter) |
| `NUCLEI_EXCLUDE_TAGS` | Nuclei template exclude tags (default: intrusive,dos,fuzz; empty = no filter) |
| `TESTSSL_CONCURRENCY` | Concurrent testssl.sh scans (default 5) |
| `SCAN_IDLE_TIMEOUT` | Scan monitor idle timeout, Go duration (default `15m`). Not applied while a scan-pipeline group holds work in flight (a pending entry delivered < 30 min ago). Not in `docker-compose.yml`: set it with a compose override; mainly for tests |
| `SCAN_MIN_RUNTIME` | Minimum scan age before a scan can complete, Go duration (default `10m`). Same as above |
| `DNS_RESOLVE_CONCURRENCY` | Concurrent subdomain DNS lookups in domain discovery (default 50); each name is published as soon as it resolves |
| `IP_ENRICHMENT_DB_PATH` | Country MMDB (DB-IP Country Lite; default `./data/dbip-country-lite.mmdb`) |
| `IP_ASN_DB_PATH` | Optional ASN MMDB (DB-IP ASN Lite; default `./data/dbip-asn-lite.mmdb`) |
| `ALLOW_PRIVATE_TARGETS` | `true` disables the private/reserved IP guard (SSRF dialer, discovery, port scanner, testssl `--ip` check, nuclei `-lna`, AXFR nameserver dial). Default `false`; enable only to scan internal networks on purpose |
| `OTEL_ENABLED` | `true` turns on OTLP trace export (default `false`); see docs/OBSERVABILITY.md |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_HEADERS` / `OTEL_SERVICE_NAME` | Standard OTLP settings |

Image-only variables (`GEO_DATA_DIR`, `GEO_DOWNLOAD`, `CLOUD_DATA_DIR`, `WAF_RULES_PATH`) are set in `scanner/Dockerfile` and `docker/entrypoint.sh`.

## Dependencies

- `github.com/redis/go-redis/v9` — Redis client with Streams
- `go.mongodb.org/mongo-driver` — MongoDB driver
- `go.uber.org/zap` — Structured logging
- `github.com/robfig/cron/v3` — Cron scheduler
- `github.com/joho/godotenv` — Env variable management
- `github.com/google/uuid` — UUID generation
- `go.opentelemetry.io/otel` — OpenTelemetry SDK
