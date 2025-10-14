# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Engine is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (discovery services, scanners) is implemented as an independent service that can be compiled and deployed separately, while sharing common infrastructure code.

**Key architectural principle:** Discovery services focus on finding assets and publish findings to Redis streams. The **ingestion service** is the single source of truth for MongoDB persistence.

## Project Structure

```
VulWall.Engine/
├── cmd/                    # Entry points for each service
│   ├── active-recon/
│   ├── passive-recon/
│   ├── shodan-discovery/   # Discovery service using Shodan
│   └── ingestion/          # Ingestion service (MongoDB persistence)
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── bootstrap/     # Common service bootstrapping
│   │   ├── config/        # Configuration loader
│   │   ├── logger/        # Zap logger setup
│   │   ├── mongox/        # MongoDB connection
│   │   └── redisx/        # Redis client & consumer groups
│   ├── shared/            # Cross-cutting concerns used by 2+ services
│   │   ├── models.go      # Shared models (DiscoveryJob, AttackSurfaceAsset)
│   │   └── constants.go   # Shared constants (streams, protocols, statuses)
│   ├── ingestion/         # Ingestion service (MongoDB persistence layer)
│   │   ├── constants.go   # Consumer group name
│   │   ├── models.go      # DiscoveryFinding model
│   │   ├── service.go     # MongoDB persistence logic
│   │   └── consumer.go    # Redis consumer
│   └── discoveries/       # Discovery services (no MongoDB access)
│       ├── active_recon/
│       │   ├── models.go       # Service-specific models
│       │   ├── constants.go    # Service-specific constants
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
│   ├── Dockerfile.ingestion
│   └── docker-compose.yml
├── scripts/               # Test and utility scripts
├── bin/                   # Compiled binaries (gitignored)
├── .env.example
├── Makefile
└── go.mod
```

**Note**: This is infrastructure-focused. No `pkg/` directory yet - external packages will be added when integrating actual scanning tools.

## Architecture Pattern

This project uses **Vertical Slice Architecture** with a **centralized ingestion layer**:

### Core Principles

1. **Discovery services** (in `internal/discoveries/`) consume jobs from `vulwall:discovery` stream
2. Discovery services perform scanning/discovery logic (NO MongoDB access)
3. Discovery services publish findings to `vulwall:discoveries` stream
4. **Ingestion service** (in `internal/ingestion/`) is the ONLY service that writes to MongoDB
5. Ingestion service consumes from `vulwall:discoveries` and persists to MongoDB

### Directory Organization

- `internal/core/` - Shared infrastructure (Redis, MongoDB, logging, config, bootstrap)
- `internal/shared/` - Models and constants used by 2+ services
- `internal/discoveries/` - Discovery services (publish findings, no MongoDB)
- `internal/ingestion/` - Ingestion service (MongoDB persistence layer)
- `cmd/` - Entry points for each service
- `ops/` - Docker and deployment files

### Communication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Discovery Architecture                       │
└─────────────────────────────────────────────────────────────────┘

1. Job Published to vulwall:discovery
   └─→ Consumed by ALL discovery services (parallel processing)

2. Discovery Services Process Jobs
   ├─→ Shodan Discovery (finds subdomains)
   ├─→ Nmap Discovery (scans ports) [future]
   └─→ Masscan Discovery (scans IPs) [future]

3. Discovery Services Publish Findings
   └─→ All publish to vulwall:discoveries stream
       ├─→ Each finding includes "source" field ("shodan", "nmap", etc.)
       └─→ Consumed by Ingestion Service

4. Ingestion Service Persists to MongoDB
   └─→ attack_surface collection
       ├─→ Creates new assets
       ├─→ Updates existing assets (last_seen)
       └─→ Handles deduplication (host + port + protocol)
```

### Model Ownership Rules

**Models belong in `internal/shared/` when used by multiple services:**

✅ **Put in `internal/shared/models.go`:**
- Models used by 2+ services
- Shared job formats (e.g., `DiscoveryJob` consumed by all discovery services)
- Shared asset models (e.g., `AttackSurfaceAsset` written by ingestion service)
- Common data structures for inter-service communication

✅ **Put in `internal/shared/constants.go`:**
- Shared stream names (e.g., `StreamDiscovery`, `StreamDiscoveries`)
- Shared collection names (e.g., `CollectionAttackSurface`)
- Protocol/status constants used by multiple services
- Target type constants

✅ **Put in `internal/discoveries/[service_name]/`:**
- Models used ONLY by that discovery service
- Service-specific business logic types
- Constants specific to that service (e.g., consumer group names)

✅ **Put in `internal/ingestion/`:**
- `DiscoveryFinding` model (consumed from vulwall:discoveries stream)
- Ingestion-specific constants (consumer group name)

❌ **DO NOT put in shared:**
- Models used by only one service
- Service-specific domain logic

**Rule of thumb:** *If a model or constant is used by 2+ services, put it in `shared/`. Otherwise, keep it in the service directory.*

### Discovery Service Architecture

Discovery services use a **parallel consumer group pattern** where multiple independent services listen to the same input stream with different consumer groups, then publish to a shared output stream:

```
Input Stream: vulwall:discovery
    ↓
    ├─→ Consumer Group: group_shodan_discovery  → Shodan Discovery Service
    ├─→ Consumer Group: group_nmap_discovery    → Nmap Discovery Service (future)
    └─→ Consumer Group: group_masscan_discovery → Masscan Discovery Service (future)
        ↓
        All publish findings to: vulwall:discoveries
        ↓
    Ingestion Service → MongoDB (attack_surface collection)
```

**Key Benefits:**
- ✅ Each discovery tool is an independent service
- ✅ All services process the same job simultaneously
- ✅ Scale each tool independently (e.g., 5 Shodan workers, 2 Nmap workers)
- ✅ Deploy/update tools independently
- ✅ Easy to add new discovery tools
- ✅ **Single source of truth for MongoDB** (ingestion service only)
- ✅ Discovery services focus on discovery logic only
- ✅ Clear separation of concerns

**How it works:**
1. Publisher sends job to `vulwall:discovery` stream
2. **All** discovery services receive the same job (different consumer groups)
3. Each service processes the job with its own tool (Shodan, Nmap, etc.)
4. Each service publishes findings to `vulwall:discoveries` stream with `source` field
5. Ingestion service consumes from `vulwall:discoveries`
6. Ingestion service persists findings to `attack_surface` collection
7. Asset deduplication handled by ingestion service (host + port + protocol)

## Common Commands

### Building Services
```bash
make build                      # Build all services
make build-passive              # Build passive-recon only
make build-active               # Build active-recon only
make build-shodan-discovery     # Build shodan-discovery only
make build-ingestion            # Build ingestion only
```

### Running Locally
```bash
make run-passive                # Run passive-recon service
make run-active                 # Run active-recon service
make run-shodan-discovery       # Run shodan-discovery service
make run-ingestion              # Run ingestion service
```

### Docker Operations
```bash
make docker-up                         # Start all services
make docker-down                       # Stop all services
make docker-scale-passive N=4          # Scale passive workers to 4
make docker-scale-active N=3           # Scale active workers to 3
make docker-scale-shodan-discovery N=2 # Scale shodan-discovery workers to 2
make docker-scale-ingestion N=3        # Scale ingestion workers to 3
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

## Adding a New Discovery Service

When adding a new discovery tool (e.g., `nmap_discovery`):

1. **Create service directory:**
   ```bash
   mkdir -p internal/discoveries/nmap_discovery
   ```

2. **Create constants (consumer group only):**
   ```bash
   # internal/discoveries/nmap_discovery/constants.go
   package nmap_discovery

   const (
       // Nmap-specific consumer group
       // Stream names are in shared.StreamDiscovery and shared.StreamDiscoveries
       GroupNmapDiscovery = "group_nmap_discovery"
   )
   ```

3. **Create service.go (NO MongoDB dependency):**
   ```go
   package nmap_discovery

   import (
       "context"
       "encoding/json"
       "github.com/go-redis/redis/v8"
       "github.com/vulwall/scanners/internal/ingestion"
       "github.com/vulwall/scanners/internal/shared"
   )

   type Service struct {
       redis      *redis.Client
       logger     *zap.Logger
       nmapClient *nmap.Client
   }

   func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
       // 1. Run nmap scan on job.Host
       // 2. For each discovered port/service, publish finding to vulwall:discoveries
       // 3. Use ingestion.DiscoveryFinding model with source="nmap"
       finding := ingestion.DiscoveryFinding{
           TraceID:  job.TraceID,
           Source:   "nmap",
           Host:     job.Host,
           Port:     &discoveredPort,
           Protocol: &protocol,
           Status:   shared.AssetStatusActive,
           Metadata: map[string]interface{}{"service": serviceName},
           Timestamp: time.Now(),
       }
       return s.publishFinding(ctx, finding)
   }

   func (s *Service) publishFinding(ctx context.Context, finding ingestion.DiscoveryFinding) error {
       data, _ := json.Marshal(finding)
       _, err := s.redis.XAdd(ctx, &redis.XAddArgs{
           Stream: shared.StreamDiscoveries,
           Values: map[string]interface{}{"data": string(data)},
       }).Result()
       return err
   }
   ```

4. **Create consumer.go:**
   ```go
   package nmap_discovery

   // Consumer reads from shared.StreamDiscovery
   // Calls service.ProcessJob()
   // NO MongoDB access
   ```

5. **Create entry point:**
   ```bash
   mkdir -p cmd/nmap-discovery
   # cmd/nmap-discovery/main.go
   ```

   ```go
   package main

   import (
       "github.com/vulwall/scanners/internal/core/bootstrap"
       "github.com/vulwall/scanners/internal/shared"
       "github.com/vulwall/scanners/internal/discoveries/nmap_discovery"
   )

   func main() {
       bootstrap.Run(bootstrap.ServiceConfig{
           ServiceName:   "nmap-discovery",
           StreamName:    shared.StreamDiscovery,
           ConsumerGroup: nmap_discovery.GroupNmapDiscovery,
           Factory: func(cfg *config.Config, redisClient *redis.Client, _ *mongo.Database, logger *zap.Logger) bootstrap.ConsumerStarter {
               return nmap_discovery.NewConsumer(redisClient, logger)
           },
       })
   }
   ```

6. **Add Docker support:**
   - Create `ops/Dockerfile.nmap-discovery`
   - Add to `ops/docker-compose.yml`
   - Update `Makefile` with build/run/scale targets

**Key Points:**
- ✅ Use `shared.StreamDiscovery` (input stream)
- ✅ Use `shared.StreamDiscoveries` (output stream)
- ✅ Use unique consumer group per tool (e.g., `group_nmap_discovery`)
- ✅ Use `shared.DiscoveryJob` for input
- ✅ Use `ingestion.DiscoveryFinding` for output
- ✅ **NO MongoDB dependency** in discovery services
- ✅ Publish findings with `source` field ("nmap", "shodan", etc.)

## Key Files

### Infrastructure (`internal/core/`)
- `bootstrap/bootstrap.go` - Common service initialization pattern (eliminates boilerplate)
- `config/config.go` - Environment-based configuration loader
- `logger/logger.go` - Zap logger initialization
- `redisx/client.go` - Redis client with consumer group helpers
- `mongox/client.go` - MongoDB connection manager

### Shared Package (`internal/shared/`)
- `models.go` - Models used by 2+ services (DiscoveryJob, AttackSurfaceAsset)
- `constants.go` - Constants used by 2+ services (streams, protocols, statuses)

### Ingestion Service (`internal/ingestion/`)
- `constants.go` - Consumer group name for ingestion service
- `models.go` - DiscoveryFinding model (consumed from vulwall:discoveries)
- `service.go` - MongoDB persistence logic (create/update assets)
- `consumer.go` - Redis consumer for vulwall:discoveries stream

### Discovery Service Pattern (`internal/discoveries/[service_name]/`)
Each discovery service is self-contained:
```
internal/discoveries/[service_name]/
├── constants.go   # Consumer group name
├── service.go     # Discovery logic, publishes findings to Redis
├── consumer.go    # Redis consumer, reads jobs from vulwall:discovery
├── models.go      # Optional: service-specific models
└── [tool]/        # Tool-specific implementation (client, API wrappers, etc.)
    └── client.go
```

### Shared Models

**DiscoveryJob** - Common job format for all discovery services (input):
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

**DiscoveryFinding** - Common finding format published by all discovery services (output):
```go
type DiscoveryFinding struct {
    TraceID   string                 // Request tracing
    Source    string                 // "shodan", "nmap", "masscan", etc.
    ParentID  *string                // Parent asset ID
    Host      string                 // Domain or IP
    Port      *int                   // Optional port number
    Protocol  *string                // tcp, udp, sctp, icmp (nil for non-port assets)
    Status    string                 // active, inactive, unknown
    Metadata  map[string]interface{} // Source-specific data
    Timestamp time.Time              // When finding was discovered
}
```

**AttackSurfaceAsset** - Asset model persisted by ingestion service (MongoDB):
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
- ✅ **Asset deduplication** - Unique by (host + port + protocol), handled by ingestion service
- ✅ **Source tracking** - Use `metadata.source` to identify discovery tool
- ✅ **Separation of concerns** - Discovery services publish, ingestion service persists

### Shared Constants

**Stream Names:**
- `shared.StreamDiscovery = "vulwall:discovery"` - Input stream for discovery jobs
- `shared.StreamDiscoveries = "vulwall:discoveries"` - Output stream for discovery findings

**Collection Names:**
- `shared.CollectionAttackSurface = "attack_surface"` - Written by ingestion service only

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
- Each service is independent - test in isolation
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
# Each service publishes findings to vulwall:discoveries
# Ingestion service persists findings to MongoDB
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

1. Make changes to a service (e.g., `internal/discoveries/shodan_discovery/`)
2. Test locally: `make run-shodan-discovery` + `make run-ingestion`
3. Verify: Publish test job to `vulwall:discovery`, check MongoDB for results
4. Build: `make build-shodan-discovery && make build-ingestion`
5. Deploy: `make docker-build && make docker-up`

## Important Notes

### Architecture
- **Each discovery service must be independent** - avoid coupling between services
- **Shared models for communication** - Use `internal/shared/` for models used by 2+ services
- **Discovery services should not access MongoDB** - only publish findings to Redis
- **Ingestion service is the single source of truth** - only it writes to MongoDB
- **Use bootstrap pattern** - All services use `bootstrap.Run()` to eliminate boilerplate

### Infrastructure
- **Cloud infrastructure** - This project uses cloud-hosted Redis and MongoDB, not self-hosted instances
- **Never commit `.env`** - only `.env.example` should be in git (contains cloud credentials)
- **Consumer groups prevent duplicate processing** - multiple workers can run safely
- **Discovery services publish to Redis** - ingestion service persists to MongoDB
- **Graceful shutdown** - Services handle SIGTERM/SIGINT properly
- **No local infrastructure needed** - All services connect to cloud databases directly

### Discovery Services Pattern
- **Parallel processing** - Multiple discovery tools process same job simultaneously
- **Independent scaling** - Scale each discovery tool independently (e.g., 5 Shodan, 2 Nmap workers)
- **Shared input stream** - `vulwall:discovery` consumed by all discovery services
- **Shared output stream** - `vulwall:discoveries` published by all discovery services
- **Unique consumer groups** - Each tool has its own group (e.g., `group_shodan_discovery`)
- **Shared models** - All use `shared.DiscoveryJob` input and `ingestion.DiscoveryFinding` output
- **Single persistence layer** - Only ingestion service writes to MongoDB
- **Asset deduplication** - Handled by ingestion service via (host + port + protocol) uniqueness
- **No organization tracking** - Assets are globally unique, org ownership tracked separately
- **Source attribution** - Use `metadata.source` to identify which tool discovered the asset

### Example: Shodan Discovery Service
```
internal/discoveries/shodan_discovery/
├── constants.go      # GroupShodanDiscovery only
├── service.go        # Uses shared.DiscoveryJob, publishes ingestion.DiscoveryFinding
├── consumer.go       # Listens to shared.StreamDiscovery with GroupShodanDiscovery
└── shodan/
    └── client.go     # Shodan API client implementation
```

**Flow:**
1. Job published to `vulwall:discovery`
2. Shodan service receives job (consumer group: `group_shodan_discovery`)
3. Discovers subdomains using Shodan API
4. Publishes finding for root domain to `vulwall:discoveries` with `source="shodan"`
5. Publishes findings for each subdomain to `vulwall:discoveries` with `source="shodan"`
6. Ingestion service consumes from `vulwall:discoveries`
7. Ingestion service creates/updates assets in MongoDB
8. All assets have `metadata.source = "shodan"`
