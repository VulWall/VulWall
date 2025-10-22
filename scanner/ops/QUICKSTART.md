# Production Deployment Quickstart

TL;DR guide to deploy VulWall NightWatch services to production.

## Prerequisites

Ensure these are installed on your Ubuntu server:

```bash
# Check if installed
docker --version
docker-compose --version
doppler --version
make --version
git --version
```

If not installed, see [full installation guide](PRODUCTION.md#initial-server-setup).

## First-Time Setup

### 1. Clone Repository

```bash
git clone https://github.com/MojtabaTajik/VulWall.NightWatch.git
cd VulWall.NightWatch
```

### 2. Login to Doppler

```bash
doppler login
```

### 3. Configure Doppler for Each Service

```bash
# Domain Discovery
cd ops/domain-discovery
doppler setup  # Select project and config
cd ../..

# Ingestion
cd ops/ingestion
doppler setup  # Select project and config
cd ../..

# Port Discovery
cd ops/port-discovery
doppler setup  # Select project and config
cd ../..
```

Make sure your Doppler configs have these secrets:

**All services:**
- `REDIS_URL`
- `MONGO_URI`
- `ENVIRONMENT`

**Domain discovery only:**
- `SHODAN_API_KEY`

### 4. Create Network and Deploy

```bash
# Create Docker network
make prod-setup

# Deploy all services
make prod-deploy-all
```

Done! Your services are now running.

## Daily Operations

### Deploy/Update Services

```bash
# Update code
git pull

# Redeploy all services
make prod-deploy-all

# Or deploy individual service
make prod-deploy-domain
make prod-deploy-ingestion
make prod-deploy-port
```

### Check Status

```bash
make prod-status
```

### View Logs

```bash
# All services
make prod-logs

# Specific service
make prod-logs SERVICE=domain-discovery

# Follow logs (real-time)
make prod-logs SERVICE=ingestion OPTS=-f
```

### Stop Services

```bash
# Stop all
make prod-stop-all

# Stop specific service
make prod-stop-service SERVICE=domain-discovery
```

### Restart Services

```bash
make prod-restart-service SERVICE=ingestion
```

## Quick Commands Reference

| Command | Description |
|---------|-------------|
| `make prod-setup` | Create Docker network (one-time) |
| `make prod-deploy-all` | Deploy all services |
| `make prod-deploy-domain` | Deploy domain-discovery |
| `make prod-deploy-ingestion` | Deploy ingestion |
| `make prod-deploy-port` | Deploy port-discovery |
| `make prod-status` | Check service health |
| `make prod-logs` | View all logs |
| `make prod-logs SERVICE=name` | View specific service logs |
| `make prod-logs OPTS=-f` | Follow logs |
| `make prod-stop-all` | Stop all services |
| `make prod-stop-service SERVICE=name` | Stop specific service |
| `make prod-restart-service SERVICE=name` | Restart service |

## Troubleshooting

### Service won't start?

```bash
# Check logs
make prod-logs SERVICE=domain-discovery

# Check if Doppler secrets are configured
cd ops/domain-discovery
doppler secrets
```

### Container not healthy?

```bash
# Check container status
docker ps -a --filter "name=nightwatch"

# View detailed container info
docker inspect nightwatch-domain-discovery

# Restart container
make prod-restart-service SERVICE=domain-discovery
```

### Connection issues?

```bash
# Test Redis
REDIS_URL=$(doppler secrets get REDIS_URL --plain)
docker run --rm redis:alpine redis-cli -u "$REDIS_URL" PING

# Test MongoDB
MONGO_URI=$(doppler secrets get MONGO_URI --plain)
docker run --rm mongo:latest mongosh "$MONGO_URI" --eval "db.adminCommand('ping')"
```

## Using Scripts Directly

Prefer scripts over Makefile? No problem:

```bash
# Deploy
./ops/scripts/deploy-all.sh
./ops/scripts/deploy-service.sh domain-discovery

# Status
./ops/scripts/status.sh

# Logs
./ops/scripts/logs.sh
./ops/scripts/logs.sh ingestion -f

# Stop
./ops/scripts/stop-all.sh
./ops/scripts/stop-service.sh domain-discovery
```

## Need More Details?

See the [complete production guide](PRODUCTION.md) for:
- Detailed setup instructions
- Monitoring strategies
- Security best practices
- Advanced troubleshooting
- Redis and MongoDB queries

---

## Emergency Commands

```bash
# Stop everything
make prod-stop-all

# View all container logs
docker logs nightwatch-domain-discovery
docker logs nightwatch-ingestion
docker logs nightwatch-port-discovery

# Restart everything
make prod-stop-all && make prod-deploy-all

# Clean Docker system (frees disk space)
docker system prune -a
```

## Support

Issues? Check:
1. Logs: `make prod-logs SERVICE=<name>`
2. Status: `make prod-status`
3. [Full production guide](PRODUCTION.md)
4. [GitHub issues](https://github.com/MojtabaTajik/VulWall.NightWatch/issues)
