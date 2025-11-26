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
| webtechprofiler | 1 |
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
│   ├── shodan.env        # SHODAN_API_KEY=... (domain-discovery only)
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

#### shodan.env (domain-discovery only)

```bash
SHODAN_API_KEY=your-shodan-api-key
```

#### honeycomb.env (optional)

```bash
HONEYCOMB_API_KEY=your-honeycomb-api-key
OTEL_EXPORTER_OTLP_ENDPOINT=api.honeycomb.io
```

### Setup

```bash
# Create directories
sudo mkdir -p /opt/vulwall/config
sudo chown $USER:$USER /opt/vulwall

# Create env files
nano /opt/vulwall/config/general.env
nano /opt/vulwall/config/redis.env
nano /opt/vulwall/config/mongo.env
nano /opt/vulwall/config/shodan.env
nano /opt/vulwall/config/honeycomb.env

# Copy MMDB file (required for IP geolocation)
cp dbip-isp-country.mmdb /opt/vulwall/
```

## Deploy

```bash
# Create Docker network (one-time)
docker network create core-network

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
