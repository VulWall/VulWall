# VulWall scanner (NightWatch)

Security asset discovery and vulnerability scanning engine for VulWall. All
components run in one Go binary, `nightwatch`, and talk to each other over
Redis streams. Results are stored in MongoDB and shown by the web app in
`../web`.

To run the whole product, use the repository-root `docker-compose.yml` (see
the root README). This file is for working on the scanner itself.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NightWatch Pipeline                              │
└─────────────────────────────────────────────────────────────────────────┘

SCAN COORDINATOR (cron schedule + scans queued by the web app in MongoDB)
    │
    ├─→ domain_discovery_queue ─→ Domain Discovery (subfinder)
    │                                    │
    │                                    ↓
    │                             domain_discovery_results
    │                                    │
    │                                    ↓
    │                             Domain Ingestion ─→ discoveries (MongoDB)
    │                                    │
    │                                    ├─→ ip_discovery_queue
    │                                    ├─→ domain_scan_triggers
    │                                    └─→ discovery_enrichment_queue
    │
    └─→ ip_discovery_queue ─→ Port Discovery (TCP Scanner)
                                         │
                                         ↓
                                  ip_discovery_results
                                         │
                                         ↓
                                  Port Ingestion ─→ discoveries (MongoDB)
                                         │
                                         └─→ port_scan_triggers

ACTIVE RECON SCANNERS (consume from scan triggers)
    ├─→ Nuclei, TestSSL, JS Dependency, HTTP Header, Email Security
    └─→ security_findings ─→ Findings Ingestion ─→ findings (MongoDB)
                                    └─→ kb_generation_queue ─→ KB engine (optional)

DISCOVERY ENRICHMENT (WAF, cloud, IP geolocation)
    └─→ discovery_enrichment_queue ─→ Enrichment ─→ Enrichment Ingestion
```

## Components

All of these run as goroutines in the `nightwatch` process
(`src/cmd/nightwatch/main.go`).

| Component | Purpose | Input Stream | Output Stream |
|---------|---------|--------------|---------------|
| **scan-coordinator** | Cron scans, queued-scan poller, scan monitor | MongoDB `scans` | domain/ip queues |
| **domain-discovery** | Subdomain discovery (subfinder) | domain_discovery_queue | domain_discovery_results |
| **port-discovery** | TCP port scanning | ip_discovery_queue | ip_discovery_results |
| **ingestion** | MongoDB persistence (5 slices) | multiple | multiple |
| **nuclei-scanner** | Vulnerability scanning | domain/port_scan_triggers | security_findings |
| **testssl-scanner** | TLS/SSL analysis | domain_scan_triggers | security_findings |
| **js-dependency-scanner** | JS library vulnerabilities (retire.js) | domain_scan_triggers | security_findings |
| **http-header-scanner** | Security header checks | domain_scan_triggers | security_findings |
| **email-security-scanner** | SPF / DMARC / DKIM checks | domain_scan_triggers | security_findings |
| **discovery-enrichment** | WAF, cloud and IP geolocation (DB-IP Lite) | discovery_enrichment_queue | discovery_enrichment_results |
| **knowledge-base-engine** | AI remediation guidance (only with `ANTHROPIC_API_KEY`) | kb_generation_queue | kb_generation_results |

## Development

### Prerequisites

- Go (version in `src/go.mod`)
- Redis 7 and MongoDB 7 (for example `docker compose up -d mongo redis` from the
  repo root, with ports published by an override file, or local installs)
- For a full local scan: `nuclei`, `testssl.sh` and `retire` on `PATH`. The
  container image has all of them; without them the matching scanners log
  errors and the rest of the pipeline still runs.

### Build, test, run

```bash
make build          # src/bin/nightwatch
make test
make vet
make run            # go run ./cmd/nightwatch (reads .env in src/ if present)
```

### Container image

```bash
docker build -t ghcr.io/vulwall/scanner ./     # from scanner/
```

The image runs as a non-root user. Volumes: `/data/nuclei-templates` and
`/data/geo` (DB-IP Lite country and ASN databases, downloaded on start).
`nightwatch healthcheck` is the container health check.

## Configuration

See the Configuration table in [CLAUDE.md](CLAUDE.md) and the repo-root
`.env.example`. Minimal local `.env`:

```bash
REDIS_URI=redis://localhost:6379/0
MONGO_URI=mongodb://localhost:27017
MONGO_DB=vulwall
# Scanners refuse private, loopback and other reserved addresses (including
# DNS answers that point there). Set to true only to scan internal networks.
ALLOW_PRIVATE_TARGETS=false
```

## Project Structure

```
Dockerfile                   # The scanner image
docker/entrypoint.sh         # Geo DB download, then exec nightwatch
src/
├── cmd/nightwatch/          # The single binary
├── internal/
│   ├── core/                # config, logger, redis, mongo, telemetry
│   ├── shared/              # Shared models and constants
│   ├── scan_coordinator/    # Scheduler, queued-scan poller, scan monitor
│   ├── discoveries/         # Domain and port discovery
│   ├── active_recon/        # Scanners and discovery enrichment
│   ├── enrichers/           # Knowledge-base engine
│   └── ingestion/           # MongoDB persistence slices
├── go.mod
└── go.sum
```

## MongoDB Collections

- **assets** - User-added assets to scan (managed via UI)
- **discoveries** - Scan results (domains, subdomains, IPs, ports) with `org_id`
- **findings** - Security vulnerabilities from scanners
- **organizations** - Org settings with `subscription_settings.scan_cron` (created by the web app)
- **scans** - Scan execution records (`queued` by the web app, claimed by the coordinator)

## Documentation

- **[CLAUDE.md](CLAUDE.md)** — Compact entry point with critical rules and quick reference
- **[docs/SERVICE_REGISTRY.md](docs/SERVICE_REGISTRY.md)** — All components, streams, consumer groups, scan monitor coverage
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Communication flows, design patterns, model ownership
- **[docs/DATABASE.md](docs/DATABASE.md)** — Go models, MongoDB schemas, scan lifecycle, finding fields
- **[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md)** — Optional OpenTelemetry tracing, logging
- **[docs/ADDING_SERVICES.md](docs/ADDING_SERVICES.md)** — How to add new components, scanners, enrichment types
