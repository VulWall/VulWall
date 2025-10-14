# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Scanners is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (passive_recon, active_recon, discovery services) is implemented as an independent "slice" that can be compiled and deployed separately, while sharing common infrastructure code.

## Project Structure

```
VulWall.Scanners/
├── cmd/                    # Entry points for each service
│   ├── active-recon/
│   ├── passive-recon/
│   └── shodan-discovery/   # Discovery service using Shodan
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── bootstrap/     # Common service bootstrapping
│   │   ├── config/        # Configuration loader
│   │   ├── logger/        # Zap logger setup
│   │   ├── mongox/        # MongoDB connection
│   │   └── redisx/        # Redis client & consumer groups
│   ├── shared/            # Cross-cutting concerns used by 2+ slices
│   │   ├── models.go      # Shared models (DiscoveryJob, AttackSurfaceAsset)
│   │   └── constants.go   # Shared constants (streams, protocols, statuses)
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
│       └── shodan_discovery/   # Shodan discovery service
│           ├── constants.go    # Consumer group name only
│           ├── service.go      # Discovery logic
│           ├── consumer.go     # Redis consumer
│           └── shodan/         # Shodan-specific client
│               └── client.go   # Shodan API client
├── ops/                   # Docker and deployment files
│   ├── Dockerfile.active-recon
│   ├── Dockerfile.passive-recon
│   ├── Dockerfile.shodan-discovery
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
- Each slice in `internal/slices/` is a bounded context with its own service logic and Redis consumer
- Shared infrastructure lives in `internal/core/` (Redis, MongoDB, logging, config, bootstrap)
- `internal/shared/` contains models and constants used by 2+ slices (see Model Ownership below)
- Each slice has its own entry point in `cmd/`
- All Docker/deployment files are organized in `ops/`

### Model Ownership Rules

**Models belong in `internal/shared/` when used by multiple slices:**

✅ **Put in `internal/shared/models.go`:**
- Models used by 2+ slices
- Shared job formats (e.g., `DiscoveryJob` consumed by all discovery services)
- Shared asset models (e.g., `AttackSurfaceAsset` written by all discovery services)
- Common data structures for inter-slice communication

✅ **Put in `internal/shared/constants.go`:**
- Shared stream names (e.g., `StreamDiscovery`)
- Shared collection names (e.g., `CollectionAttackSurface`)
- Protocol/status constants used by multiple services
- Target type constants

✅ **Put in `internal/slices/[slice_name]/`:**
- Models used ONLY by that slice
- Slice-specific business logic types
- Job/Result types specific to that scanner (unless shared)
- Constants specific to that slice (e.g., consumer group names)

❌ **DO NOT put in shared:**
- Models used by only one slice
- Slice-specific domain logic

**Rule of thumb:** *If a model or constant is used by 2+ slices, put it in `shared/`. Otherwise, keep it in the slice.*

### Discovery Service Architecture (New Pattern)

The discovery services use a **parallel consumer group pattern** where multiple independent services listen to the same stream with different consumer groups:

```
Redis Stream: vulwall:discovery (shared)
    ↓
    ├─→ Consumer Group: group_shodan_discovery  → Shodan Discovery Service
    ├─→ Consumer Group: group_nmap_discovery    → Nmap Discovery Service (future)
    └─→ Consumer Group: group_masscan_discovery → Masscan Discovery Service (future)

All services write to: MongoDB → attack_surface collection
```

**Key Benefits:**
- ✅ Each discovery tool is an independent service
- ✅ All services process the same job simultaneously
- ✅ Scale each tool independently (e.g., 5 Shodan workers, 2 Nmap workers)
- ✅ Deploy/update tools independently
- ✅ Easy to add new discovery tools

**How it works:**
1. Publisher sends job to `vulwall:discovery` stream
2. **All** discovery services receive the same job (different consumer groups)
3. Each service processes the job with its own tool (Shodan, Nmap, etc.)
4. All services write discovered assets to `attack_surface` collection
5. Asset deduplication handled by unique constraint (host + port + protocol)

### Communication Flow
1. Jobs are published to Redis Streams (e.g., `vulwall:passive_recon`, `vulwall:discovery`)
2. Consumer workers read from streams using consumer groups
3. Business logic in `service.go` processes the job
4. Results are saved to MongoDB collections (e.g., `passive_recon`, `attack_surface`)

## Common Commands

### Building Services
```bash
make build                      # Build all services
make build-passive              # Build passive-recon only
make build-active               # Build active-recon only
make build-shodan-discovery     # Build shodan-discovery only
```

### Running Locally
```bash
make run-passive                # Run passive-recon service
make run-active                 # Run active-recon service
make run-shodan-discovery       # Run shodan-discovery service
```

### Docker Operations
```bash
make docker-up                         # Start all services
make docker-down                       # Stop all services
make docker-scale-passive N=4          # Scale passive workers to 4
make docker-scale-active N=3           # Scale active workers to 3
make docker-scale-shodan-discovery N=2 # Scale shodan-discovery workers to 2
make docker-logs                       # View logs
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

## Adding a New Vertical Slice (Traditional Pattern)

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

**Important:** Each slice is self-contained. Only add models to `internal/shared/` if they're used by multiple slices.

## Adding a New Discovery Service (Parallel Consumer Pattern)

When adding a new discovery tool (e.g., `nmap_discovery`):

1. **Create slice directory:**
   ```bash
   mkdir -p internal/slices/nmap_discovery
   ```

2. **Create constants (consumer group only):**
   ```bash
   # internal/slices/nmap_discovery/constants.go
   package nmap_discovery

   const (
       // Nmap-specific consumer group
       // Stream name (vulwall:discovery) is in shared.StreamDiscovery
       // Collection name (attack_surface) is in shared.CollectionAttackSurface
       GroupNmapDiscovery = "group_nmap_discovery"
   )
   ```

3. **Create service.go:**
   ```go
   package nmap_discovery

   import (
       "context"
       "github.com/vulwall/scanners/internal/shared"
       "github.com/vulwall/scanners/internal/slices/nmap_discovery/nmap"
   )

   type Service struct {
       db         *mongo.Database
       logger     *zap.Logger
       nmapClient *nmap.Client
   }

   func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
       // 1. Check if asset exists (optional - create if doesn't exist)
       // 2. Run nmap scan on job.Host
       // 3. Create discovered assets (ports, services) in attack_surface collection
       // 4. Use shared.AttackSurfaceAsset model
   }
   ```

4. **Create consumer.go:**
   ```go
   package nmap_discovery

   import (
       "github.com/vulwall/scanners/internal/shared"
   )

   func (c *Consumer) processMessages(ctx context.Context, consumerName string) error {
       streams, err := c.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
           Group:    GroupNmapDiscovery,              // Unique consumer group
           Consumer: consumerName,
           Streams:  []string{shared.StreamDiscovery, ">"}, // Shared stream
           Count:    1,
           Block:    5 * time.Second,
       }).Result()
       // ... process job using shared.DiscoveryJob
   }
   ```

5. **Create tool-specific client:**
   ```bash
   # internal/slices/nmap_discovery/nmap/client.go
   # Implement Nmap scanning logic
   ```

6. **Create entry point:**
   ```bash
   mkdir -p cmd/nmap-discovery
   # cmd/nmap-discovery/main.go
   ```

   ```go
   package main

   import (
       "github.com/vulwall/scanners/internal/core/bootstrap"
       "github.com/vulwall/scanners/internal/shared"
       "github.com/vulwall/scanners/internal/slices/nmap_discovery"
   )

   func main() {
       bootstrap.Run(bootstrap.ServiceConfig{
           ServiceName:   "nmap-discovery",
           StreamName:    shared.StreamDiscovery,              // Shared stream
           ConsumerGroup: nmap_discovery.GroupNmapDiscovery,   // Unique group
           Factory: func(cfg *config.Config, redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
               return nmap_discovery.NewConsumer(redisClient, db, logger)
           },
       })
   }
   ```

7. **Add Docker support:**
   - Create `ops/Dockerfile.nmap-discovery`
   - Add to `ops/docker-compose.yml`
   - Update `Makefile`

**Key Points:**
- Use `shared.StreamDiscovery` (same stream as other discovery services)
- Use unique consumer group per tool (e.g., `group_nmap_discovery`)
- Use `shared.DiscoveryJob` for input
- Use `shared.AttackSurfaceAsset` for output
- Write to `shared.CollectionAttackSurface`

## Key Files

### Infrastructure (`internal/core/`)
- `bootstrap/bootstrap.go` - Common service initialization pattern (eliminates boilerplate)
- `config/config.go` - Environment-based configuration loader
- `logger/logger.go` - Zap logger initialization
- `redisx/client.go` - Redis client with consumer group helpers
- `mongox/client.go` - MongoDB connection manager

### Shared Package (`internal/shared/`)
- `models.go` - Models used by 2+ slices (DiscoveryJob, AttackSurfaceAsset)
- `constants.go` - Constants used by 2+ slices (streams, protocols, statuses)

### Vertical Slice Pattern
Each slice is self-contained:
```
internal/slices/[slice_name]/
├── constants.go   # Slice-specific constants (consumer group, etc.)
├── service.go     # Core business logic, implements ProcessXxx()
├── consumer.go    # Redis consumer, reads jobs → calls service → saves results
├── models.go      # Optional: slice-specific models (if not using shared)
└── [tool]/        # Tool-specific implementation (client, API wrappers, etc.)
    └── client.go
```

### Shared Models

**DiscoveryJob** - Common job format for all discovery services:
```go
type DiscoveryJob struct {
    TraceID  string                 // Request tracing
    ParentID *string                // Parent asset ID (for recursive discovery)
    Host     string                 // Domain or IP to discover
    Port     *int                   // Optional: specific port to scan
    Protocol *string                // Optional: tcp, udp, sctp, icmp
    Metadata map[string]interface{} // Provider-specific metadata
    Created  time.Time
}
```

**AttackSurfaceAsset** - Common asset model written by all discovery services:
```go
type AttackSurfaceAsset struct {
    ID        string                 // UUID
    ParentID  *string                // Parent asset (e.g., root domain)
    Host      string                 // Domain or IP
    Port      *int                   // Optional port number
    Protocol  *string                // tcp, udp, sctp, icmp (nil for non-port assets)
    Status    string                 // active, inactive, unknown
    FirstSeen time.Time
    LastSeen  time.Time
    Metadata  map[string]interface{} // Source-specific data (e.g., {"source": "shodan"})
}
```

**Key Design Decisions:**
- ❌ **No `org_id` field** - Assets are globally unique, organization ownership tracked separately
- ✅ **Protocol-aware** - `192.168.1.1:53/tcp` ≠ `192.168.1.1:53/udp`
- ✅ **Asset deduplication** - Unique by (host + port + protocol)
- ✅ **Source tracking** - Use `metadata.source` to identify discovery tool

### Shared Constants

**Stream Names:**
- `shared.StreamDiscovery = "vulwall:discovery"` - Shared by all discovery services

**Collection Names:**
- `shared.CollectionAttackSurface = "attack_surface"` - Written by all discovery services

**Protocols:**
- `shared.ProtocolTCP`, `ProtocolUDP`, `ProtocolSCTP`, `ProtocolICMP`

**Target Types:**
- `shared.TargetTypeDomain`, `TargetTypeIP`, `TargetTypeCIDR`

**Asset Status:**
- `shared.AssetStatusActive`, `AssetStatusInactive`, `AssetStatusUnknown`

## Configuration

**This project uses cloud-hosted Redis and MongoDB.** Services load config from environment variables or `.env` file:

- `REDIS_ADDR` - Cloud Redis endpoint (e.g., `redis-12345.cloud.redislabs.com:12345`)
- `REDIS_PASSWORD` - Redis authentication password (required for cloud)
- `REDIS_DB` - Redis database number (default: 0)
- `MONGO_URI` - MongoDB Atlas/Cloud connection string (e.g., `mongodb+srv://user:pass@cluster.mongodb.net/`)
- `MONGO_DB` - Database name (default: vulwall)
- `ENVIRONMENT` - development/production (affects logging)
- `SHODAN_API_KEY` - Shodan API key for subdomain discovery (shodan-discovery service)

See `.env.example` for full list and examples.

## Testing Strategy

- Unit tests for service logic should mock Redis/MongoDB
- Integration tests should use testcontainers
- Each slice is independent - test in isolation
- Shared core packages should have comprehensive tests

## Publishing Discovery Jobs

To trigger discovery across all discovery services:

```bash
# Publish to shared stream - ALL discovery services receive this
redis-cli XADD vulwall:discovery * data '{
  "trace_id": "trace-123",
  "host": "example.com",
  "created": "2025-10-14T10:00:00Z"
}'

# Result: Shodan finds subdomains, Nmap scans ports, etc. - all simultaneously
```

**Job with specific port/protocol:**
```bash
redis-cli XADD vulwall:discovery * data '{
  "trace_id": "trace-456",
  "host": "192.168.1.1",
  "port": 443,
  "protocol": "tcp",
  "created": "2025-10-14T10:00:00Z"
}'
```

## Dependencies

- `github.com/go-redis/redis/v8` - Redis client with Streams support
- `go.mongodb.org/mongo-driver` - Official MongoDB driver
- `go.uber.org/zap` - Structured logging
- `github.com/joho/godotenv` - Environment variable management
- `github.com/google/uuid` - Consumer name generation

## Development Workflow

1. Make changes to a slice (e.g., `internal/slices/shodan_discovery/`)
2. Test locally: `make run-shodan-discovery`
3. Verify: Publish test job to Redis, check MongoDB for results
4. Build: `make build-shodan-discovery`
5. Deploy: `make docker-build && make docker-up`

## Important Notes

### Architecture
- **Each slice must be independent** - avoid coupling between slices
- **Shared models for communication** - Use `internal/shared/` for models used by 2+ slices
- **Slices should not import other slices** - only import from `core/` and `shared/`
- **Use bootstrap pattern** - All services use `bootstrap.Run()` to eliminate boilerplate
- **Discovery services use parallel consumer pattern** - Same stream, different consumer groups

### Infrastructure
- **Cloud infrastructure** - This project uses cloud-hosted Redis and MongoDB, not self-hosted instances
- **Never commit `.env`** - only `.env.example` should be in git (contains cloud credentials)
- **Consumer groups prevent duplicate processing** - multiple workers can run safely
- **Results are written to MongoDB** - Redis is only for job queuing
- **Graceful shutdown** - Services handle SIGTERM/SIGINT properly
- **No local infrastructure needed** - All services connect to cloud databases directly

### Discovery Services Pattern
- **Parallel processing** - Multiple discovery tools process same job simultaneously
- **Independent scaling** - Scale each discovery tool independently (e.g., 5 Shodan, 2 Nmap workers)
- **Shared stream** - `vulwall:discovery` consumed by all discovery services
- **Unique consumer groups** - Each tool has its own group (e.g., `group_shodan_discovery`)
- **Shared models** - All use `shared.DiscoveryJob` input and `shared.AttackSurfaceAsset` output
- **Asset deduplication** - MongoDB handles via unique constraint on (host + port + protocol)
- **No organization tracking** - Assets are globally unique, org ownership tracked separately
- **Source attribution** - Use `metadata.source` to identify which tool discovered the asset

### Example: Shodan Discovery Service
```
internal/slices/shodan_discovery/
├── constants.go      # GroupShodanDiscovery only
├── service.go        # Uses shared.DiscoveryJob, writes shared.AttackSurfaceAsset
├── consumer.go       # Listens to shared.StreamDiscovery with GroupShodanDiscovery
└── shodan/
    └── client.go     # Shodan API client implementation
```

**Flow:**
1. Job published to `vulwall:discovery`
2. Shodan service receives job (consumer group: `group_shodan_discovery`)
3. Creates root asset if doesn't exist
4. Triggers subdomain discovery for domains
5. Writes discovered subdomains as child assets
6. All assets have `metadata.source = "shodan"`
