# VulWall NightWatch

Security asset discovery and vulnerability scanning platform built with Go microservices.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NightWatch Pipeline                              │
└─────────────────────────────────────────────────────────────────────────┘

SCAN COORDINATOR (automated scheduling)
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
    ├─→ Nuclei Scanner ─→ security_findings ─→ Findings Ingestion
    ├─→ TestSSL Scanner ─→ security_findings ─→ Findings Ingestion
    ├─→ WebTechProfiler ─→ security_findings ─→ Findings Ingestion
    └─→ JS Dependency Scanner ─→ security_findings ─→ Findings Ingestion

DISCOVERY ENRICHMENT (WAF + IP Geolocation)
    └─→ discovery_enrichment_queue ─→ Enrichment ─→ Enrichment Ingestion
```

## Services

| Service | Purpose | Input Stream | Output Stream |
|---------|---------|--------------|---------------|
| **scan-coordinator** | Automated scan scheduling | - | domain/ip queues |
| **domain-discovery** | Subdomain discovery (subfinder) | domain_discovery_queue | domain_discovery_results |
| **port-discovery** | TCP port scanning | ip_discovery_queue | ip_discovery_results |
| **ingestion** | MongoDB persistence (5 slices) | multiple | multiple |
| **nuclei-scanner** | Vulnerability scanning | domain/port_scan_triggers | security_findings |
| **testssl-scanner** | TLS/SSL analysis | domain_scan_triggers | security_findings |
| **webtechprofiler** | Web technology detection | domain_scan_triggers | security_findings |
| **js-dependency-scanner** | JS library vulnerabilities | domain_scan_triggers | security_findings |
| **discovery-enrichment** | WAF + IP geolocation | discovery_enrichment_queue | discovery_enrichment_results |

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- Cloud Redis (Redis Cloud, etc.)
- Cloud MongoDB (Atlas, etc.)

### Run Locally

```bash
# Build all services
make build

# Run discovery services
make run-domain-discovery
make run-port-discovery

# Run ingestion (required)
make run-ingestion

# Run active recon scanners
make run-nuclei-scanner
make run-testssl-scanner

# Run scan coordinator (automated scans)
make run-scan-coordinator
```

### Docker Deployment

```bash
# Deploy all services
make prod-deploy-all

# Check status
make prod-status

# View logs
make prod-logs SERVICE=ingestion OPTS=-f
```

## Configuration

Environment variables (`.env`):

```bash
REDIS_URI=redis://user:pass@host:port/db
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/db
ENVIRONMENT=production
```

## Project Structure

```
src/                         # Go source code
├── cmd/
│   ├── discoveries/
│   │   ├── domain-discovery/    # subfinder subdomain discovery
│   │   └── port-discovery/      # TCP port scanner
│   ├── active_recon/
│   │   ├── nuclei-scanner/      # Nuclei vulnerability scanner
│   │   ├── testssl-scanner/     # TLS/SSL scanner
│   │   ├── webtechprofiler/     # Web tech detection
│   │   ├── js-dependency-scanner/  # JS vulnerability scanner
│   │   └── discovery-enrichment/   # WAF + geolocation
│   ├── ingestion/               # MongoDB persistence orchestrator
│   └── scan-coordinator/        # Automated scan scheduler
├── internal/
│   ├── core/                    # Shared infrastructure (bootstrap, config, redis, mongo)
│   ├── shared/                  # Shared models and constants
│   ├── discoveries/             # Discovery service implementations
│   ├── active_recon/            # Active recon scanner implementations
│   ├── ingestion/               # Ingestion slice implementations
│   └── scan_coordinator/        # Scan coordinator implementation
├── go.mod
└── go.sum
ops/                         # Docker, compose, deploy scripts
```

## MongoDB Collections

- **assets** - User-added assets to scan (managed via UI)
- **discoveries** - Scan results (domains, subdomains, IPs, ports) with `org_id`
- **findings** - Security vulnerabilities from scanners
- **organizations** - Org settings with `scan_interval_days`
- **scans** - Scan execution records

## Documentation

- **[CLAUDE.md](CLAUDE.md)** — Compact entry point with critical rules and quick reference
- **[docs/SERVICE_REGISTRY.md](docs/SERVICE_REGISTRY.md)** — All services, streams, consumer groups, scan monitor coverage
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Communication flows, design patterns, model ownership
- **[docs/DATABASE.md](docs/DATABASE.md)** — Go models, MongoDB schemas, query examples
- **[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md)** — OpenTelemetry tracing patterns
- **[docs/ADDING_SERVICES.md](docs/ADDING_SERVICES.md)** — How to add new services, scanners, enrichment types
- **[ops/PRODUCTION.md](ops/PRODUCTION.md)** — Production deployment guide

## Development

```bash
make build          # Build all services
make test           # Run tests
make fmt            # Format code
make lint           # Run linter
```
