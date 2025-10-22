# VulWall NightWatch - Operations & Deployment

This directory contains deployment configurations and scripts for VulWall NightWatch services.

## Directory Structure

```
ops/
├── domain-discovery/         # Domain discovery service
│   ├── Dockerfile
│   └── docker-compose.yml
├── ingestion/                # Ingestion service
│   ├── Dockerfile
│   └── docker-compose.yml
├── port-discovery/           # Port discovery service
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/                  # Deployment scripts
│   ├── setup-network.sh      # Create Docker network
│   ├── deploy-all.sh         # Deploy all services
│   ├── deploy-service.sh     # Deploy single service
│   ├── stop-all.sh           # Stop all services
│   ├── stop-service.sh       # Stop single service
│   ├── restart-service.sh    # Restart single service
│   ├── logs.sh               # View service logs
│   └── status.sh             # Check service status
├── PRODUCTION.md             # Complete production deployment guide
├── QUICKSTART.md             # Quick start guide (TL;DR)
└── README.md                 # This file
```

## Quick Links

- **[QUICKSTART.md](QUICKSTART.md)** - Fast guide to deploy services (5 minutes)
- **[PRODUCTION.md](PRODUCTION.md)** - Complete production deployment guide (detailed)

## Deployment Overview

### Architecture

VulWall NightWatch uses a **microservices architecture** with 3 independent services:

1. **Domain Discovery** - Discovers subdomains using Shodan API
2. **Ingestion** - Processes findings and stores in MongoDB
3. **Port Discovery** - Scans ports on discovered IPs

All services:
- Communicate via Redis Streams
- Share a Docker network (`core-network`)
- Use Doppler for secrets management
- Run as Docker containers

### Secrets Management

This project uses **Doppler** for production secrets:

- **No `.env` files in git** - All secrets stored in Doppler
- Deployment scripts automatically download secrets from Doppler
- Each service has its own Doppler configuration

Required secrets:
- `REDIS_URI` - Redis Cloud connection string
- `MONGO_URI` - MongoDB Atlas connection string
- `SHODAN_API_KEY` - Shodan API key (domain-discovery only)
- `ENVIRONMENT` - Environment name (production)

## Quick Start

### Prerequisites

On your Ubuntu server:
```bash
# Install Docker, Docker Compose, Doppler CLI, Make
# See PRODUCTION.md for installation commands
```

### Deploy Services

```bash
# 1. Clone repository
git clone https://github.com/MojtabaTajik/VulWall.NightWatch.git
cd VulWall.NightWatch

# 2. Login to Doppler
doppler login

# 3. Setup Doppler for each service
cd ops/domain-discovery && doppler setup && cd ../..
cd ops/ingestion && doppler setup && cd ../..
cd ops/port-discovery && doppler setup && cd ../..

# 4. Create network
make prod-setup

# 5. Deploy all services
make prod-deploy-all
```

### Common Commands

```bash
# Deploy
make prod-deploy-all              # Deploy all services
make prod-deploy-domain           # Deploy domain-discovery
make prod-deploy-ingestion        # Deploy ingestion
make prod-deploy-port             # Deploy port-discovery

# Monitor
make prod-status                  # Check service health
make prod-logs                    # View all logs
make prod-logs SERVICE=ingestion  # View specific service logs

# Manage
make prod-stop-all                            # Stop all services
make prod-stop-service SERVICE=domain-discovery  # Stop specific service
make prod-restart-service SERVICE=ingestion      # Restart service
```

## Using Scripts Directly

Prefer shell scripts? All Makefile targets are wrappers around scripts:

```bash
# Deploy
./ops/scripts/deploy-all.sh
./ops/scripts/deploy-service.sh domain-discovery

# Monitor
./ops/scripts/status.sh
./ops/scripts/logs.sh ingestion -f

# Manage
./ops/scripts/stop-all.sh
./ops/scripts/stop-service.sh domain-discovery
```

## Service Details

### Domain Discovery

- **Purpose:** Discovers subdomains using Shodan API
- **Container:** `nightwatch-domain-discovery`
- **Directory:** `ops/domain-discovery/`
- **Input:** `domain_discovery_queue` Redis stream
- **Output:** `domain_discovery_results` Redis stream
- **Secrets:** `REDIS_URI`, `MONGO_URI`, `SHODAN_API_KEY`

### Ingestion

- **Purpose:** Processes findings and stores in MongoDB
- **Container:** `nightwatch-ingestion`
- **Directory:** `ops/ingestion/`
- **Input:** `domain_discovery_results`, `ip_discovery_results` Redis streams
- **Output:** MongoDB `discoveries` and `org_assets` collections
- **Secrets:** `REDIS_URI`, `MONGO_URI`

### Port Discovery

- **Purpose:** Scans ports on discovered IPs
- **Container:** `nightwatch-port-discovery`
- **Directory:** `ops/port-discovery/`
- **Input:** `ip_discovery_queue` Redis stream
- **Output:** `ip_discovery_results` Redis stream
- **Secrets:** `REDIS_URI`, `MONGO_URI`

## Deployment Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    Production Deployment                     │
└─────────────────────────────────────────────────────────────┘

1. Git Pull
   ↓
2. Doppler Downloads Secrets → .env files
   ↓
3. Docker Build (multi-stage builds)
   ↓
4. Stop Existing Containers
   ↓
5. Start New Containers
   ↓
6. Health Check (wait for healthy status)
   ↓
7. Deployment Complete ✓
```

## Monitoring

### Service Status

```bash
# Quick status check
make prod-status

# Docker stats
docker stats --filter "name=nightwatch"

# Container health
docker ps --filter "name=nightwatch"
```

### Logs

```bash
# All services
make prod-logs

# Specific service
make prod-logs SERVICE=domain-discovery

# Follow logs (real-time)
make prod-logs SERVICE=ingestion OPTS=-f

# Last 100 lines
make prod-logs SERVICE=port-discovery OPTS="--tail=100"
```

### Redis Monitoring

```bash
# Get Redis URI
REDIS_URI=$(doppler secrets get REDIS_URI --plain)

# Check queue lengths
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN domain_discovery_queue
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN ip_discovery_queue
```

### MongoDB Monitoring

```bash
# Get MongoDB URI
MONGO_URI=$(doppler secrets get MONGO_URI --plain)

# Connect to MongoDB
docker run --rm -it mongo:latest mongosh "$MONGO_URI"

# Count discoveries
db.discoveries.countDocuments()
```

## Troubleshooting

### Logs showing errors?

```bash
# View detailed logs
make prod-logs SERVICE=domain-discovery

# Check container status
docker inspect nightwatch-domain-discovery

# Restart service
make prod-restart-service SERVICE=domain-discovery
```

### Can't connect to Redis/MongoDB?

```bash
# Test Redis connection
REDIS_URL=$(doppler secrets get REDIS_URL --plain)
docker run --rm redis:alpine redis-cli -u "$REDIS_URL" PING

# Test MongoDB connection
MONGO_URI=$(doppler secrets get MONGO_URI --plain)
docker run --rm mongo:latest mongosh "$MONGO_URI" --eval "db.adminCommand('ping')"
```

### Doppler authentication failed?

```bash
# Re-authenticate
doppler login

# Verify
doppler me

# Re-setup service
cd ops/domain-discovery
doppler setup
```

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Quick deployment guide
- **[PRODUCTION.md](PRODUCTION.md)** - Comprehensive production guide
- **[Project README](../README.md)** - Project overview and architecture
- **[CLAUDE.md](../CLAUDE.md)** - Codebase structure and development guide

## Security Notes

⚠️ **IMPORTANT:**

- **NEVER commit `.env` files** to git
- `.env` files are automatically generated by deployment scripts
- All secrets stored securely in Doppler
- `.env` files ignored by `.gitignore`

## Support

Need help?

1. Check [PRODUCTION.md](PRODUCTION.md) troubleshooting section
2. View service logs: `make prod-logs SERVICE=<name>`
3. Check service status: `make prod-status`
4. Create GitHub issue: https://github.com/MojtabaTajik/VulWall.NightWatch/issues

---

**Quick Deploy:** `make prod-deploy-all`

**View Logs:** `make prod-logs`

**Check Status:** `make prod-status`
