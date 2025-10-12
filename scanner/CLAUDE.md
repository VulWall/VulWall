# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Scanners is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (passive_recon, active_recon) is implemented as an independent "slice" that can be compiled and deployed separately, while sharing common infrastructure code.

## Project Structure

```
VulWall.Scanners/
├── cmd/                    # Entry points for each service
│   ├── active-recon/
│   └── passive-recon/
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── config/
│   │   ├── logger/
│   │   ├── mongox/
│   │   └── redisx/
│   ├── shared/            # Domain models and constants
│   └── slices/            # Vertical slices (bounded contexts)
│       ├── active_recon/
│       └── passive_recon/
├── ops/                   # Docker and deployment files
│   ├── Dockerfile.active-recon
│   ├── Dockerfile.passive-recon
│   └── docker-compose.yml
├── bin/                   # Compiled binaries (gitignored)
├── .env.example
├── Makefile
└── go.mod
```

**Note**: This is infrastructure-focused. No `pkg/` directory yet - external packages will be added when integrating actual scanning tools.

## Architecture Pattern

This project uses **Vertical Slice Architecture**:
- Each slice in `internal/slices/` is a bounded context with its own service logic and Redis consumer
- Shared infrastructure lives in `internal/core/` (Redis, MongoDB, logging, config)
- Common domain models are in `internal/shared/`
- Each slice has its own entry point in `cmd/`
- All Docker/deployment files are organized in `ops/`

### Communication Flow
1. Jobs are published to Redis Streams (e.g., `vulwall:passive_recon`)
2. Consumer workers read from streams using consumer groups
3. Business logic in `service.go` processes the job
4. Results are saved to MongoDB collections (e.g, `passive_recon` collection)

## Common Commands

### Building Services
```bash
make build                  # Build all services
make build-passive          # Build passive-recon only
make build-active           # Build active-recon only
```

### Running Locally
```bash
make run-passive            # Run passive-recon service
make run-active             # Run active-recon service
```

### Docker Operations
```bash
make docker-up              # Start all services
make docker-down            # Stop all services
make docker-scale-passive N=4  # Scale passive workers to 4
make docker-logs            # View logs
```

### Testing
```bash
make test                   # Run all tests
make test-coverage          # Run tests with coverage report
```

### Code Quality
```bash
make fmt                    # Format code
make lint                   # Run linter
make vet                    # Run go vet
make deps                   # Download and tidy dependencies
```

## Adding a New Vertical Slice

When adding a new scanner type (e.g., `vuln_scan`):

1. **Create slice directory structure:**
   ```bash
   mkdir -p internal/slices/vuln_scan
   ```

2. **Implement core files:**
   - `service.go` - Contains `ProcessScan()` method with scan logic
   - `consumer.go` - Redis stream consumer that reads jobs and calls service
   - Pattern: Copy from `internal/slices/passive_recon/` and adapt

3. **Add constants to `internal/shared/constants.go`:**
   ```go
   StreamVulnScan = "vulwall:vuln_scan"
   GroupVulnScan  = "vuln_scan_group"
   ```

4. **Create entry point:**
   ```bash
   mkdir -p cmd/vuln-scan
   # Create cmd/vuln-scan/main.go - copy from cmd/passive-recon and adapt
   ```

5. **Add Docker support:**
   - Create `ops/Dockerfile.vuln-scan` (all Docker files are in ops/ directory)
   - Add service to `ops/docker-compose.yml`
   - Makefile already uses `ops/docker-compose.yml` for all Docker commands

6. **Update models if needed:**
   - Add result types to `internal/shared/models.go`
   - Ensure `ScanResult.Results` can handle your result type

## Key Files

### Infrastructure (`internal/core/`)
- `config/config.go` - Environment-based configuration loader
- `logger/logger.go` - Zap logger initialization
- `redisx/client.go` - Redis client with consumer group helpers
- `mongox/client.go` - MongoDB connection manager

### Models (`internal/shared/`)
- `models.go` - `ScanJob`, `ScanResult`, and result type structs
- `constants.go` - Stream names, consumer groups, collection names, status constants

### Example Slice Pattern
Each slice follows this structure:
```
internal/slices/[slice_name]/
├── service.go    # Core business logic, implements ProcessScan()
└── consumer.go   # Redis consumer, reads jobs → calls service → saves results
```

## Configuration

**This project uses cloud-hosted Redis and MongoDB.** Services load config from environment variables or `.env` file:

- `REDIS_ADDR` - Cloud Redis endpoint (e.g., `redis-12345.cloud.redislabs.com:12345`)
- `REDIS_PASSWORD` - Redis authentication password (required for cloud)
- `REDIS_DB` - Redis database number (default: 0)
- `MONGO_URI` - MongoDB Atlas/Cloud connection string (e.g., `mongodb+srv://user:pass@cluster.mongodb.net/`)
- `MONGO_DB` - Database name (default: vulwall)
- `ENVIRONMENT` - development/production (affects logging)

See `.env.example` for full list and examples.

## Testing Strategy

- Unit tests for service logic should mock Redis/MongoDB
- Integration tests should use testcontainers
- Each slice is independent - test in isolation
- Shared core packages should have comprehensive tests

## Dependencies

- `github.com/go-redis/redis/v8` - Redis client with Streams support
- `go.mongodb.org/mongo-driver` - Official MongoDB driver
- `go.uber.org/zap` - Structured logging
- `github.com/joho/godotenv` - Environment variable management
- `github.com/google/uuid` - Consumer name generation

## Development Workflow

1. Make changes to a slice (e.g., `internal/slices/passive_recon/`)
2. Test locally: `make run-passive`
3. Verify: Publish test job to Redis, check MongoDB for results
4. Build: `make build-passive`
5. Deploy: `make docker-build && make docker-up`

## Important Notes

- **Cloud infrastructure** - This project uses cloud-hosted Redis and MongoDB, not self-hosted instances
- **Never commit `.env`** - only `.env.example` should be in git (contains cloud credentials)
- **Each slice must be independent** - avoid coupling between slices
- **Shared code only in `core/` and `shared/`** - slices should not import other slices
- **Consumer groups prevent duplicate processing** - multiple workers can run safely
- **Results are written to MongoDB** - Redis is only for job queuing
- **Graceful shutdown** - Services handle SIGTERM/SIGINT properly
- **No local infrastructure needed** - All services connect to cloud databases directly
