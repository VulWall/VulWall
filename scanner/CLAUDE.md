# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Scanners is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (passive_recon, active_recon) is implemented as an independent "slice" that can be compiled and deployed separately, while sharing common infrastructure code.

## Project Structure

```
VulWall.Scanners/
├── cmd/                    # Entry points for each service
│   ├── active-recon/
│   ├── passive-recon/
│   └── attack-surface/
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── bootstrap/     # Common service bootstrapping
│   │   ├── config/        # Configuration loader
│   │   ├── logger/        # Zap logger setup
│   │   ├── mongox/        # MongoDB connection
│   │   └── redisx/        # Redis client & consumer groups
│   ├── shared/            # ONLY truly cross-cutting concerns
│   └── slices/            # Vertical slices (bounded contexts)
│       ├── active_recon/
│       │   ├── models.go       # Slice-specific models
│       │   ├── constants.go    # Slice-specific constants
│       │   ├── service.go      # Business logic
│       │   └── consumer.go     # Redis consumer
│       ├── passive_recon/
│       │   ├── models.go
│       │   ├── constants.go
│       │   ├── service.go
│       │   └── consumer.go
│       └── attack_surface/
│           ├── models.go
│           ├── constants.go
│           ├── service.go
│           ├── consumer.go
│           └── discovery/      # Attack surface discovery providers
│               ├── provider.go          # Provider interface
│               ├── manager.go           # Discovery orchestration
│               ├── shodan.go            # Shodan API client
│               └── shodan_provider.go   # Shodan provider implementation
├── ops/                   # Docker and deployment files
│   ├── Dockerfile.active-recon
│   ├── Dockerfile.passive-recon
│   ├── Dockerfile.attack-surface
│   └── docker-compose.yml
├── scripts/               # Test and utility scripts
├── bin/                   # Compiled binaries (gitignored)
├── .env.example
├── Makefile
└── go.mod
```

**Note**: This is infrastructure-focused. No `pkg/` directory yet - external packages will be added when integrating actual scanning tools.

## Architecture Pattern

This project uses **Vertical Slice Architecture**:
- Each slice in `internal/slices/` is a bounded context with its own models, service logic, and Redis consumer
- Shared infrastructure lives in `internal/core/` (Redis, MongoDB, logging, config, bootstrap)
- `internal/shared/` contains ONLY truly cross-cutting concerns (see Model Ownership below)
- Each slice has its own entry point in `cmd/`
- All Docker/deployment files are organized in `ops/`

### Model Ownership Rules

**Each slice OWNS its own models** - this is critical for independence:

✅ **Put in `internal/slices/[slice_name]/models.go`:**
- Models used ONLY by that slice
- Slice-specific business logic types
- Job/Result types specific to that scanner

✅ **Put in `internal/shared/`:**
- Truly cross-cutting infrastructure (e.g., `Config`)
- Used by 2+ slices for communication
- Common interfaces between slices
- Shared value objects

❌ **DO NOT put in shared:**
- Models used by only one slice
- Slice-specific domain logic

**Rule of thumb:** *If you delete a slice and a shared model becomes unused, it shouldn't have been in shared.*

### Communication Flow
1. Jobs are published to Redis Streams (e.g., `vulwall:passive_recon`)
2. Consumer workers read from streams using consumer groups
3. Business logic in `service.go` processes the job
4. Results are saved to MongoDB collections (e.g, `passive_recon` collection)

## Common Commands

### Building Services
```bash
make build                      # Build all services
make build-passive              # Build passive-recon only
make build-active               # Build active-recon only
make build-attack-surface       # Build attack-surface only
```

### Running Locally
```bash
make run-passive                # Run passive-recon service
make run-active                 # Run active-recon service
make run-attack-surface         # Run attack-surface service
```

### Docker Operations
```bash
make docker-up                      # Start all services
make docker-down                    # Stop all services
make docker-scale-passive N=4       # Scale passive workers to 4
make docker-scale-active N=3        # Scale active workers to 3
make docker-scale-attack-surface N=2 # Scale attack-surface workers to 2
make docker-logs                    # View logs
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

2. **Create slice-specific models:**
   ```bash
   # internal/slices/vuln_scan/models.go
   # Define Job, Result, and all domain models for THIS slice only
   ```

3. **Create slice-specific constants:**
   ```bash
   # internal/slices/vuln_scan/constants.go
   const (
       StreamVulnScan        = "vulwall:vuln_scan"
       GroupVulnScan         = "vuln_scan_group"
       CollectionVulnScan    = "vuln_scan"
       StatusPending         = "pending"
       StatusRunning         = "running"
       StatusCompleted       = "completed"
       StatusFailed          = "failed"
   )
   ```

4. **Implement core files:**
   - `service.go` - Contains `ProcessScan()` method with scan logic
   - `consumer.go` - Redis stream consumer that reads jobs and calls service
   - Pattern: Copy from `internal/slices/passive_recon/` and adapt

5. **Create entry point using bootstrap:**
   ```bash
   mkdir -p cmd/vuln-scan
   # Create cmd/vuln-scan/main.go - copy from cmd/passive-recon and adapt
   # Use bootstrap.Run() to eliminate boilerplate
   ```

6. **Add Docker support:**
   - Create `ops/Dockerfile.vuln-scan`
   - Add service to `ops/docker-compose.yml`
   - Update `Makefile` with build/run/scale targets

7. **Add test script if needed:**
   ```bash
   # Create scripts/test_vuln_scan.sh to publish test jobs to Redis
   ```

**Important:** Each slice is self-contained. DO NOT add models to `internal/shared/` unless they're truly used by multiple slices.

## Key Files

### Infrastructure (`internal/core/`)
- `bootstrap/bootstrap.go` - Common service initialization pattern (eliminates boilerplate)
- `config/config.go` - Environment-based configuration loader
- `logger/logger.go` - Zap logger initialization
- `redisx/client.go` - Redis client with consumer group helpers
- `mongox/client.go` - MongoDB connection manager

### Shared Package (`internal/shared/`)
- Contains ONLY truly cross-cutting concerns
- Currently minimal by design (vertical slice independence)
- Add only when 2+ slices need to communicate

### Vertical Slice Pattern
Each slice is completely self-contained:
```
internal/slices/[slice_name]/
├── models.go      # Slice-specific models (Job, Result, domain types)
├── constants.go   # Stream names, collection names, status constants
├── service.go     # Core business logic, implements ProcessXxx()
├── consumer.go    # Redis consumer, reads jobs → calls service → saves results
└── [subdir]/      # Optional: additional tools/modules (e.g., discovery/)
```

**Example: attack_surface slice with pluggable discovery providers**
```
internal/slices/attack_surface/
├── models.go           # AttackSurfaceJob, AttackSurfaceAsset (includes Protocol field)
├── constants.go        # StreamAttackSurface, AssetStatusActive, ProtocolTCP/UDP, TargetTypeDomain/IP
├── service.go          # ProcessJob(), asset deduplication logic (protocol-aware)
├── consumer.go         # Redis consumer for attack surface jobs
└── discovery/          # Pluggable provider architecture
    ├── provider.go             # AttackSurfaceProvider interface
    ├── manager.go              # Discovery orchestration across multiple providers
    ├── shodan.go               # Shodan API client (low-level)
    └── shodan_provider.go      # Shodan provider implementation
```

## Configuration

**This project uses cloud-hosted Redis and MongoDB.** Services load config from environment variables or `.env` file:

- `REDIS_ADDR` - Cloud Redis endpoint (e.g., `redis-12345.cloud.redislabs.com:12345`)
- `REDIS_PASSWORD` - Redis authentication password (required for cloud)
- `REDIS_DB` - Redis database number (default: 0)
- `MONGO_URI` - MongoDB Atlas/Cloud connection string (e.g., `mongodb+srv://user:pass@cluster.mongodb.net/`)
- `MONGO_DB` - Database name (default: vulwall)
- `ENVIRONMENT` - development/production (affects logging)
- `SHODAN_API_KEY` - Shodan API key for subdomain discovery (attack-surface service)

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

### Architecture
- **Each slice must be independent** - avoid coupling between slices
- **Each slice owns its models** - DO NOT add slice-specific models to `shared/`
- **Slices should not import other slices** - only import from `core/` and `shared/`
- **Use bootstrap pattern** - All services use `bootstrap.Run()` to eliminate boilerplate
- **Models stay in their slice** - Only truly cross-cutting types go in `shared/`

### Infrastructure
- **Cloud infrastructure** - This project uses cloud-hosted Redis and MongoDB, not self-hosted instances
- **Never commit `.env`** - only `.env.example` should be in git (contains cloud credentials)
- **Consumer groups prevent duplicate processing** - multiple workers can run safely
- **Results are written to MongoDB** - Redis is only for job queuing
- **Graceful shutdown** - Services handle SIGTERM/SIGINT properly
- **No local infrastructure needed** - All services connect to cloud databases directly

### Integration Examples
- **Shodan Integration** - attack_surface service uses Shodan DNS domain API for subdomain discovery
- **Modular design** - Discovery tools are organized in subdirectories (e.g., `discovery/shodan.go`)
- **Background processing** - Subdomain discovery runs asynchronously for root domains
