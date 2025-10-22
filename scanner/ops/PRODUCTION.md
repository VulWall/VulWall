# Production Deployment Guide

Complete guide for deploying VulWall NightWatch services to your Ubuntu production server.

## Table of Contents

- [Initial Server Setup](#initial-server-setup)
- [Doppler Configuration](#doppler-configuration)
- [Deployment](#deployment)
- [Managing Services](#managing-services)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Initial Server Setup

### 1. Server Requirements

- **OS:** Ubuntu 20.04 LTS or newer
- **RAM:** 4GB minimum, 8GB recommended
- **CPU:** 2 cores minimum, 4 cores recommended
- **Disk:** 20GB minimum
- **Network:** Outbound access to Redis Cloud and MongoDB Atlas

### 2. Install Docker

```bash
# Update package list
sudo apt update

# Install prerequisites
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# Add your user to docker group (logout/login required)
sudo usermod -aG docker $USER

# Verify installation
docker --version
```

### 3. Install Docker Compose

```bash
# Download Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Make executable
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker-compose --version
```

### 4. Install Doppler CLI

```bash
# Install Doppler CLI
curl -Ls --tlsv1.2 --proto "=https" --retry 3 https://cli.doppler.com/install.sh | sudo sh

# Verify installation
doppler --version
```

### 5. Install Make (if not installed)

```bash
sudo apt install -y make

# Verify installation
make --version
```

### 6. Install Git

```bash
sudo apt install -y git

# Configure git (optional)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

---

## Doppler Configuration

### 1. Login to Doppler

```bash
# Login to Doppler (opens browser)
doppler login

# Verify authentication
doppler me
```

### 2. Create Doppler Projects

You need to create a Doppler project and configure secrets for each service.

#### Option A: Single Project (Recommended for Simple Setup)

Create one project with different configs for each service:

```bash
# Create project (do this in Doppler web UI)
# Project name: vulwall-nightwatch

# Create configs:
# - domain-discovery
# - ingestion
# - port-discovery
```

#### Option B: Separate Projects

Create a separate project for each service (more isolation).

### 3. Add Secrets to Doppler

For each service config, add the following secrets:

**All Services:**
```
REDIS_URI=redis://:<password>@<host>:<port>/<db>
MONGO_URI=mongodb+srv://<user>:<password>@<cluster>.mongodb.net/<database>?retryWrites=true&w=majority
ENVIRONMENT=production
```

**Domain Discovery Only:**
```
SHODAN_API_KEY=your-shodan-api-key
```

### 4. Setup Doppler for Each Service

```bash
cd /path/to/VulWall.NightWatch

# Setup for domain-discovery
cd ops/domain-discovery
doppler setup
# Select your project and config

# Setup for ingestion
cd ../ingestion
doppler setup
# Select your project and config

# Setup for port-discovery
cd ../port-discovery
doppler setup
# Select your project and config

# Return to project root
cd ../..
```

After setup, each service directory will have a `.doppler.yaml` file with the project/config settings.

---

## Deployment

### 1. Clone Repository

```bash
# Clone the repository
git clone https://github.com/MojtabaTajik/VulWall.NightWatch.git
cd VulWall.NightWatch

# Checkout production branch (if you have one)
# git checkout main
```

### 2. Initial Setup

```bash
# Create Docker network
make prod-setup
```

### 3. Deploy All Services

```bash
# Deploy all services at once
make prod-deploy-all

# Or deploy with explicit Doppler project/config
make prod-deploy-all PROJECT=vulwall-nightwatch CONFIG=prd
```

This will:
1. Download secrets from Doppler to `.env` files
2. Build Docker images for each service
3. Stop existing containers (if running)
4. Start new containers
5. Wait for healthchecks to pass
6. Report deployment status

### 4. Deploy Individual Services

```bash
# Deploy only domain-discovery
make prod-deploy-domain

# Deploy only ingestion
make prod-deploy-ingestion

# Deploy only port-discovery
make prod-deploy-port

# With explicit Doppler config
make prod-deploy-domain PROJECT=vulwall-nightwatch CONFIG=prd
```

---

## Managing Services

### Check Service Status

```bash
# Check all services
make prod-status

# Or use Docker directly
docker ps --filter "name=nightwatch"
```

### View Logs

```bash
# View logs from all services
make prod-logs

# View logs from specific service
make prod-logs SERVICE=domain-discovery

# Follow logs (real-time)
make prod-logs SERVICE=ingestion OPTS=-f

# Last 100 lines
make prod-logs SERVICE=port-discovery OPTS="--tail=100"
```

### Stop Services

```bash
# Stop all services
make prod-stop-all

# Stop specific service
make prod-stop-service SERVICE=domain-discovery
```

### Restart Services

```bash
# Restart specific service
make prod-restart-service SERVICE=ingestion

# Restart with Doppler config
make prod-restart-service SERVICE=domain-discovery PROJECT=vulwall-nightwatch CONFIG=prd
```

### Update and Redeploy

```bash
# Pull latest code
git pull origin main

# Redeploy all services
make prod-deploy-all

# Or redeploy specific service
make prod-deploy-domain
```

---

## Alternative: Using Scripts Directly

You can also use the shell scripts directly instead of Makefile:

```bash
# Setup network
./ops/scripts/setup-network.sh

# Deploy all services
./ops/scripts/deploy-all.sh

# Deploy specific service
./ops/scripts/deploy-service.sh domain-discovery
./ops/scripts/deploy-service.sh ingestion vulwall-nightwatch prd

# Stop services
./ops/scripts/stop-all.sh
./ops/scripts/stop-service.sh domain-discovery

# View logs
./ops/scripts/logs.sh
./ops/scripts/logs.sh domain-discovery -f

# Check status
./ops/scripts/status.sh
```

---

## Monitoring

### Service Health

```bash
# Check all services health
make prod-status

# View Docker stats
docker stats --filter "name=nightwatch"
```

### Redis Streams (Check Queue Lengths)

```bash
# Get REDIS_URI from Doppler
REDIS_URI=$(doppler secrets get REDIS_URI --plain --project vulwall-nightwatch --config prd)

# Check queue lengths
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN domain_discovery_queue
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN ip_discovery_queue
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN domain_discovery_results
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XLEN ip_discovery_results

# Check consumer groups
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XINFO GROUPS domain_discovery_queue
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" XINFO GROUPS ip_discovery_queue
```

### MongoDB Queries

```bash
# Get MONGO_URI from Doppler
MONGO_URI=$(doppler secrets get MONGO_URI --plain --project vulwall-nightwatch --config prd)

# Connect to MongoDB
docker run --rm -it mongo:latest mongosh "$MONGO_URI"

# Example queries:
# Show all databases
show dbs

# Use vulwall database
use vulwall

# Count discoveries
db.discoveries.countDocuments()

# Count org_assets
db.org_assets.countDocuments()

# Recent discoveries
db.discoveries.find().sort({last_seen: -1}).limit(10)
```

### Log Monitoring

```bash
# Follow logs from all services
make prod-logs OPTS=-f

# Search logs for errors
docker logs nightwatch-domain-discovery 2>&1 | grep -i error
docker logs nightwatch-ingestion 2>&1 | grep -i error
docker logs nightwatch-port-discovery 2>&1 | grep -i error
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
make prod-logs SERVICE=domain-discovery

# Check if container exists
docker ps -a --filter "name=nightwatch"

# Check Docker network
docker network inspect core-network

# Verify .env file exists and has secrets
ls -la ops/domain-discovery/.env
cat ops/domain-discovery/.env
```

### Doppler Authentication Issues

```bash
# Re-authenticate
doppler login

# Verify authentication
doppler me

# Re-setup project
cd ops/domain-discovery
doppler setup
```

### Network Issues

```bash
# Recreate network
docker network rm core-network
make prod-setup

# Check network connectivity
docker network inspect core-network

# Test container network connectivity
docker run --rm --network core-network alpine ping -c 3 google.com
```

### Container Healthcheck Failing

```bash
# Check logs for errors
make prod-logs SERVICE=domain-discovery

# Inspect container
docker inspect nightwatch-domain-discovery

# Check if process is running inside container
docker exec nightwatch-domain-discovery pgrep -x domain-discovery

# Manually restart container
docker restart nightwatch-domain-discovery
```

### Redis Connection Issues

```bash
# Test Redis connection
REDIS_URI=$(doppler secrets get REDIS_URI --plain --project vulwall-nightwatch --config prd)
docker run --rm redis:alpine redis-cli -u "$REDIS_URI" PING

# Expected output: PONG
```

### MongoDB Connection Issues

```bash
# Test MongoDB connection
MONGO_URI=$(doppler secrets get MONGO_URI --plain --project vulwall-nightwatch --config prd)
docker run --rm mongo:latest mongosh "$MONGO_URI" --eval "db.adminCommand('ping')"

# Expected output: { ok: 1 }
```

### Disk Space Issues

```bash
# Check disk space
df -h

# Clean up Docker
docker system prune -a --volumes

# Remove old images
docker images | grep vulwall | awk '{print $3}' | xargs docker rmi -f
```

### Memory Issues

```bash
# Check memory usage
free -h

# Check Docker memory usage
docker stats --no-stream

# Restart services to free memory
make prod-stop-all
make prod-deploy-all
```

---

## Security Best Practices

### 1. Secrets Management

- ✅ **NEVER** commit `.env` files to git
- ✅ Use Doppler for all secrets
- ✅ Rotate secrets regularly
- ✅ Use different secrets for dev/staging/production

### 2. Network Security

- ✅ Configure firewall (UFW)
- ✅ Whitelist your server IP in Redis Cloud
- ✅ Whitelist your server IP in MongoDB Atlas
- ✅ Use TLS/SSL for all database connections
- ✅ Close unused ports

### 3. Container Security

- ✅ Run containers as non-root user (already done in Dockerfiles)
- ✅ Keep base images updated
- ✅ Scan images for vulnerabilities
- ✅ Limit container resources if needed

### 4. Access Control

- ✅ Use SSH keys (disable password authentication)
- ✅ Limit sudo access
- ✅ Enable firewall
- ✅ Keep server updated

---

## Updating Services

### Pull Latest Code and Redeploy

```bash
# SSH to server
ssh user@your-server

# Navigate to project
cd /path/to/VulWall.NightWatch

# Pull latest code
git pull origin main

# Redeploy services
make prod-deploy-all
```

### Rollback to Previous Version

```bash
# Find previous commit
git log --oneline

# Checkout previous commit
git checkout <commit-hash>

# Redeploy
make prod-deploy-all

# Return to latest
git checkout main
```

---

## Production Checklist

Before going to production, ensure:

- [ ] Docker and Docker Compose installed
- [ ] Doppler CLI installed and authenticated
- [ ] Doppler projects/configs created with all secrets
- [ ] Docker network created (`make prod-setup`)
- [ ] Firewall configured
- [ ] Redis Cloud IP whitelist configured
- [ ] MongoDB Atlas IP whitelist configured
- [ ] TLS/SSL enabled for databases
- [ ] All services deployed successfully
- [ ] Healthchecks passing
- [ ] Logs showing no errors
- [ ] Redis streams working (check queue lengths)
- [ ] MongoDB collections created
- [ ] Backup strategy in place
- [ ] Monitoring/alerting configured (optional)

---

## Quick Reference

### Common Commands

```bash
# Deploy
make prod-deploy-all
make prod-deploy-domain

# Status
make prod-status

# Logs
make prod-logs
make prod-logs SERVICE=ingestion OPTS=-f

# Stop
make prod-stop-all
make prod-stop-service SERVICE=domain-discovery

# Restart
make prod-restart-service SERVICE=ingestion
```

### Service Directories

- Domain Discovery: `ops/domain-discovery/`
- Ingestion: `ops/ingestion/`
- Port Discovery: `ops/port-discovery/`

### Container Names

- `nightwatch-domain-discovery`
- `nightwatch-ingestion`
- `nightwatch-port-discovery`

### Network

- `core-network` (external Docker network shared by all services)

---

## Support

For issues or questions:

1. Check logs: `make prod-logs SERVICE=<name>`
2. Check status: `make prod-status`
3. Review troubleshooting section above
4. Check GitHub issues: https://github.com/MojtabaTajik/VulWall.NightWatch/issues
