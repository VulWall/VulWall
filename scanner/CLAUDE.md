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
│           └── discovery/      # Attack surface discovery framework
│               ├── provider.go          # Provider interface
│               ├── manager.go           # Discovery orchestration
│               └── shodan/              # Shodan provider (subdirectory per provider)
│                   ├── client.go        # Shodan API client
│                   └── provider.go      # Provider implementation
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
    ├── shodan/                 # Shodan provider (each provider in own subdirectory)
    │   ├── client.go           # Shodan API client (low-level)
    │   └── provider.go         # Provider implementation
    ├── nmap/                   # Future: Nmap provider
    │   ├── client.go
    │   └── provider.go
    └── masscan/                # Future: Masscan provider
        ├── client.go
        └── provider.go
```

## Discovery Provider Pattern (Attack Surface Slice)

The attack_surface slice implements a **pluggable provider architecture** for discovering assets (subdomains, IPs, ports, services):

### Architecture Overview

```
Service (asset management)
    ↓
Discovery Manager (orchestrator)
    ↓
Multiple Providers (Shodan, Nmap, Masscan, etc.)
```

### Key Components

1. **Provider Interface** (`discovery/provider.go`)
   ```go
   type AttackSurfaceProvider interface {
       Name() string
       Discover(ctx context.Context, target DiscoveryTarget) ([]DiscoveredAsset, error)
   }
   ```

2. **Discovery Manager** (`discovery/manager.go`)
   - Orchestrates multiple providers
   - Handles asset deduplication
   - Creates/updates assets in MongoDB
   - Runs providers in sequence (or parallel in future)

3. **Provider Implementations**
   - `ShodanProvider` - Discovers subdomains via Shodan DNS API
   - Future: `NmapProvider`, `MasscanProvider`, `CensysProvider`, etc.

### Protocol-Aware Asset Model

Assets now include **Protocol** field to differentiate:
- `192.168.1.1:53/tcp` vs `192.168.1.1:53/udp` are separate assets
- Subdomains have `Protocol: nil`
- Port scans specify protocol: `tcp`, `udp`, `sctp`, `icmp`

**Model Structure:**
```go
type AttackSurfaceAsset struct {
    ID        string
    OrgID     string      // Organization ID for multi-tenant grouping
    ParentID  *string     // Parent asset (e.g., root domain)
    Host      string      // Domain or IP
    Port      *int        // Optional port number
    Protocol  *string     // tcp, udp, sctp, icmp (nil for non-port assets)
    Status    string      // active, inactive, unknown
    FirstSeen time.Time
    LastSeen  time.Time
    Metadata  map[string]interface{}
}
```

### Constants

**Protocols:** `ProtocolTCP`, `ProtocolUDP`, `ProtocolSCTP`, `ProtocolICMP`
**Target Types:** `TargetTypeDomain`, `TargetTypeIP`, `TargetTypeCIDR`
**Asset Status:** `AssetStatusActive`, `AssetStatusInactive`, `AssetStatusUnknown`

### Adding a New Discovery Provider

1. **Create provider directory:**
   ```bash
   mkdir internal/slices/attack_surface/discovery/myprovider
   ```

2. **Create API client:** `discovery/myprovider/client.go`
   ```go
   package myprovider

   import (
       "context"
       "go.uber.org/zap"
   )

   type Client struct {
       apiKey string
       logger *zap.Logger
   }

   func NewClient(apiKey string, logger *zap.Logger) *Client {
       return &Client{apiKey: apiKey, logger: logger}
   }

   func (c *Client) DiscoverAssets(ctx context.Context, target string) ([]string, error) {
       // API interaction logic here
   }
   ```

3. **Implement provider:** `discovery/myprovider/provider.go`
   ```go
   package myprovider

   import (
       "context"
       "github.com/vulwall/scanners/internal/slices/attack_surface/discovery"
       "go.uber.org/zap"
   )

   type Provider struct {
       client *Client
       logger *zap.Logger
   }

   func NewProvider(apiKey string, logger *zap.Logger) *Provider {
       return &Provider{
           client: NewClient(apiKey, logger),
           logger: logger,
       }
   }

   func (p *Provider) Name() string {
       return "myprovider"
   }

   func (p *Provider) Discover(ctx context.Context, target discovery.DiscoveryTarget) ([]discovery.DiscoveredAsset, error) {
       // Discovery logic here
       // Return []discovery.DiscoveredAsset with Host, Port, Protocol, Metadata
   }
   ```

4. **Register in service:** Add to `NewService()` in `service.go`:
   ```go
   import (
       "github.com/vulwall/scanners/internal/slices/attack_surface/discovery/myprovider"
   )

   providers := []discovery.AttackSurfaceProvider{
       shodan.NewProvider(shodanAPIKey, logger),
       myprovider.NewProvider(myAPIKey, logger),  // Add here
   }
   ```

### Benefits

✅ **Separation of Concerns** - Service handles asset management, providers handle discovery
✅ **Pluggable** - Add/remove providers without changing core service logic
✅ **Testable** - Mock providers easily for unit tests
✅ **Protocol-Aware** - TCP/UDP differentiation built into model
✅ **Scalable** - Manager can run providers in parallel (future enhancement)
✅ **Configuration-Driven** - Enable/disable providers via config

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
- **Pluggable Discovery Architecture** - attack_surface uses provider pattern for extensible discovery
- **Shodan Integration** - Each provider has its own package: `discovery/shodan/` with `client.go` and `provider.go`
- **Protocol-Aware Assets** - Assets differentiate TCP vs UDP on same port (e.g., `192.168.1.1:53/tcp` vs `192.168.1.1:53/udp`)
- **Modular design** - Each provider isolated in its own subdirectory under `discovery/`
- **Background processing** - Discovery runs asynchronously for root assets (no parent)
- **Orchestration** - Discovery Manager coordinates multiple providers and handles deduplication
- **Scalable structure** - Easy to add new providers: create `discovery/[provider]/` with `client.go` and `provider.go`
- **Future-Ready** - Architecture ready for Nmap (`discovery/nmap/`), Masscan (`discovery/masscan/`), Censys, Certificate Transparency providers
