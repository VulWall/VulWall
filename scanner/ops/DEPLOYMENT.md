# Production Deployment Guide

## Prerequisites

```bash
docker --version         # Docker 20.10+
docker-compose --version # Docker Compose 2.0+
make --version           # GNU Make
```

## Services

| Service | Default Replicas |
|---------|-----------------|
| scan-coordinator | 1 (singleton) |
| domain-discovery | 1 |
| port-discovery | 1 |
| ingestion | 1 |
| nuclei-scanner | 5 |
| testssl-scanner | 5 |
| js-dependency-scanner | 1 |
| discovery-enrichment | 1 |

## Configuration

All services read configuration from `/opt/vulwall/config/` directory.

### Required Files

```text
/opt/vulwall/
├── config/
│   ├── general.env       # ENVIRONMENT=production
│   ├── redis.env         # REDIS_URI=redis://...
│   ├── mongo.env         # MONGO_URI=mongodb+srv://...
│   └── honeycomb.env     # HONEYCOMB_API_KEY=... (optional, for tracing)
└── dbip-isp-country.mmdb # IP geolocation database (ingestion, discovery-enrichment)
```

### Environment Files

#### general.env

```bash
ENVIRONMENT=production
```

#### redis.env

```bash
REDIS_URI=redis://user:password@host:port/db
```

#### mongo.env

```bash
MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/vulwall
```

#### honeycomb.env (optional)

```bash
HONEYCOMB_API_KEY=your-honeycomb-api-key
OTEL_EXPORTER_OTLP_ENDPOINT=api.honeycomb.io
```

### Setup

The `server-setup.sh` script handles all first-time setup automatically (idempotent — safe to re-run):

```bash
# Run the setup script (installs Docker, creates directories, downloads GeoIP DB)
./ops/scripts/server-setup.sh
```

This script:
1. Installs Docker + Docker Compose (if missing)
2. Creates `/opt/vulwall/config/` directory
3. Creates `core-network` Docker network (if missing)
4. Downloads the GeoIP database to `/opt/vulwall/dbip-isp-country.mmdb` (if missing)
5. Validates that config files exist

After running the setup script, create the env files:

```bash
nano /opt/vulwall/config/general.env
nano /opt/vulwall/config/redis.env
nano /opt/vulwall/config/mongo.env
nano /opt/vulwall/config/honeycomb.env
```

### Server Hardening (First-Time Only)

SSH into the new server as root and run the hardening script **before** `server-setup.sh`:

```bash
# Harden the server (creates deploy user, UFW, SSH, Fail2ban, Docker daemon, kernel)
./server-harden.sh

# Skip auditd if not needed
./server-harden.sh --skip-auditd
```

> **NOTE:** The script will ask you to paste your SSH public key (e.g. `ssh-ed25519 AAAA...`). Generate one locally with `ssh-keygen -t ed25519` if you don't have one. This key will be used for the deploy user and CI/CD access. After SSH hardening, only the `deploy` user can login via key-based auth — root and password login are disabled.

This script is idempotent — safe to re-run. It configures:
1. Deploy user (`deploy`) with Docker group + scoped passwordless sudo for CI/CD
2. UFW firewall (allow SSH only — Docker manages its own ports)
3. SSH hardening via drop-in config (key-only auth, no root login, session limits)
4. Fail2ban (SSH brute-force protection: 3 retries, 2h ban)
5. Unattended-upgrades (automatic daily security patches)
6. File permissions (`600` on `.env` files, `700` on config dir)
7. Docker daemon (`no-new-privileges`, `live-restore`, log rotation: 10MB x 3 files)
8. Kernel hardening via sysctl (anti-spoofing, ASLR, ICMP hardening)
9. Timezone set to UTC
10. Swap file (2GB, prevents OOM kills from memory-hungry scanners)
11. Auditd rules for `/opt/vulwall/config/` monitoring (optional)

## Deploy

```bash
# Deploy all services
make prod-deploy-all

# Or deploy individual services
make prod-deploy-domain
make prod-deploy-port
make prod-deploy-ingestion
make prod-deploy-scan-coordinator
make prod-deploy-nuclei
make prod-deploy-testssl
```

## Manage

```bash
# Status
make prod-status

# Logs
make prod-logs                              # All services
make prod-logs SERVICE=ingestion OPTS=-f    # Follow specific service

# Stop
make prod-stop-all
make prod-stop-service SERVICE=domain-discovery

# Restart
make prod-restart-service SERVICE=ingestion
```

## Redis Streams

| Stream | Purpose |
|--------|---------|
| domain_discovery_queue | Domain discovery jobs |
| domain_discovery_results | Domain discovery findings |
| ip_discovery_queue | Port discovery jobs |
| ip_discovery_results | Port discovery findings |
| domain_scan_triggers | Active recon triggers (domains) |
| port_scan_triggers | Active recon triggers (ports) |
| security_findings | Vulnerability findings |
| discovery_enrichment_queue | Enrichment jobs |
| discovery_enrichment_results | Enrichment results |

## MongoDB Collections

| Collection | Purpose |
|------------|---------|
| assets | User-added assets to scan |
| discoveries | Scan results (domains, IPs, ports) |
| findings | Security vulnerabilities |
| organizations | Org settings |
| scans | Scan execution records |

## Troubleshooting

### Service won't start

```bash
# Check logs
make prod-logs SERVICE=domain-discovery

# Check env files exist
ls -la /opt/vulwall/config/
```

### Connection issues

```bash
# Test Redis
docker run --rm redis:alpine redis-cli -u "$(cat /opt/vulwall/config/redis.env | grep REDIS_URI | cut -d= -f2)" PING

# Test MongoDB
docker run --rm mongo:latest mongosh "$(cat /opt/vulwall/config/mongo.env | grep MONGO_URI | cut -d= -f2)" --eval "db.adminCommand('ping')"
```

### Clean restart

```bash
make prod-stop-all
docker system prune -f
make prod-deploy-all
```

## Security

- Keep `/opt/vulwall/config/` files readable only by the user running Docker
- Whitelist server IP in Redis Cloud and MongoDB Atlas
- Run containers as non-root (configured in Dockerfiles)
