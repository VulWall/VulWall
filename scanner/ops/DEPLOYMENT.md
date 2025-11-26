# Production Deployment Guide

## Prerequisites

```bash
# Required on Ubuntu server
docker --version         # Docker 20.10+
docker-compose --version # Docker Compose 2.0+
doppler --version        # Doppler CLI
make --version           # GNU Make
```

## Services

| Service | Container Name | Replicas |
|---------|---------------|----------|
| domain-discovery | nightwatch-domain-discovery | 1-2 |
| port-discovery | nightwatch-port-discovery | 1-5 |
| ingestion | nightwatch-ingestion | 1-3 |
| scan-coordinator | nightwatch-scan-coordinator | 1 (singleton) |
| nuclei-scanner | nightwatch-nuclei-scanner | 1-3 |
| testssl-scanner | nightwatch-testssl-scanner | 1-2 |
| webtechprofiler | nightwatch-webtechprofiler | 1-2 |
| js-dependency-scanner | nightwatch-js-dependency-scanner | 1-2 |
| discovery-enrichment | nightwatch-discovery-enrichment | 1-2 |

## Quick Deploy

```bash
# 1. Clone and setup
git clone <repo-url>
cd VulWall.NightWatch

# 2. Configure Doppler for each service
doppler login
cd ops/domain-discovery && doppler setup && cd ../..
cd ops/ingestion && doppler setup && cd ../..
# ... repeat for each service

# 3. Create network and deploy
make prod-setup
make prod-deploy-all
```

## Required Secrets (Doppler)

**All services:**
```
REDIS_URI=redis://user:pass@host:port/db
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/db
ENVIRONMENT=production
```

**Domain discovery only:**
```
SHODAN_API_KEY=your-api-key
```

## Commands

### Deploy

```bash
make prod-deploy-all                  # Deploy all services
make prod-deploy-domain               # Deploy domain-discovery
make prod-deploy-ingestion            # Deploy ingestion
make prod-deploy-port                 # Deploy port-discovery
make prod-deploy-scan-coordinator     # Deploy scan-coordinator
make prod-deploy-nuclei               # Deploy nuclei-scanner
```

### Monitor

```bash
make prod-status                      # Check all services
make prod-logs                        # View all logs
make prod-logs SERVICE=ingestion      # View specific service
make prod-logs SERVICE=ingestion OPTS=-f  # Follow logs
```

### Manage

```bash
make prod-stop-all                    # Stop all services
make prod-stop-service SERVICE=name   # Stop specific service
make prod-restart-service SERVICE=name # Restart service
```

## Data Directory

Required for IP geolocation (MMDB database):

```bash
# Create directory
sudo mkdir -p /opt/vulwall
sudo chown $USER:$USER /opt/vulwall

# Copy MMDB file
cp dbip-isp-country.mmdb /opt/vulwall/
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

### Monitor Redis

```bash
REDIS_URI=$(doppler secrets get REDIS_URI --plain)
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN domain_discovery_queue
```

## MongoDB Collections

| Collection | Purpose |
|------------|---------|
| assets | User-added assets to scan |
| discoveries | Scan results (domains, IPs, ports) |
| findings | Security vulnerabilities |
| organizations | Org settings |
| scans | Scan execution records |

### Monitor MongoDB

```bash
MONGO_URI=$(doppler secrets get MONGO_URI --plain)
docker run --rm -it mongo:latest mongosh "$MONGO_URI" --eval "db.discoveries.countDocuments()"
```

## Troubleshooting

### Service won't start

```bash
# Check logs
make prod-logs SERVICE=domain-discovery

# Verify Doppler secrets
cd ops/domain-discovery && doppler secrets
```

### Connection issues

```bash
# Test Redis
REDIS_URI=$(doppler secrets get REDIS_URI --plain)
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" PING

# Test MongoDB
MONGO_URI=$(doppler secrets get MONGO_URI --plain)
docker run --rm mongo:latest mongosh "$MONGO_URI" --eval "db.adminCommand('ping')"
```

### Clean restart

```bash
make prod-stop-all
docker system prune -f
make prod-deploy-all
```

## Security

- Never commit `.env` files
- Use Doppler for all secrets
- Whitelist server IP in Redis Cloud and MongoDB Atlas
- Run containers as non-root (configured in Dockerfiles)
