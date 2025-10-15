# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VulWall Engine is a **vertically-sliced Go monorepo** for security scanning services. Each feature domain (discovery services, scanners) is implemented as an independent service that can be compiled and deployed separately, while sharing common infrastructure code.

**Key architectural principles:**
- Discovery services focus on finding assets and publish findings to Redis streams
- The **ingestion service** uses **vertical slice architecture** with concurrent consumers
- All jobs MUST include `org_id` (organization GUID) or they will be skipped
- **Domain discoveries:** Shodan domains stored in `org_domains` collection with IP resolution history
- **Port discoveries:** Port scans stored in `attack_surface` + `org_attack_surface` collections (normalized design)

## Project Structure

```
VulWall.Engine/
├── cmd/                    # Entry points for each service
│   ├── active-recon/
│   ├── passive-recon/
│   ├── domain-discovery/   # Domain discovery service (Shodan)
│   ├── port-discovery/     # Port discovery service (TCP scanner)
│   └── ingestion/          # Ingestion orchestrator (MongoDB persistence)
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── bootstrap/     # Common service bootstrapping
│   │   ├── config/        # Configuration loader
│   │   ├── logger/        # Zap logger setup
│   │   ├── mongox/        # MongoDB connection
│   │   └── redisx/        # Redis client & consumer groups
│   ├── shared/            # Cross-cutting concerns used by 2+ services
│   │   ├── models.go      # Shared models (DiscoveryJob, IPDiscoveryJob, etc.)
│   │   └── constants.go   # Shared constants (streams, protocols, statuses)
│   ├── ingestion/         # Ingestion service (vertical slice architecture)
│   │   ├── orchestrator.go      # Runs all consumers concurrently
│   │   ├── domain_ingestion/    # Domain ingestion slice
│   │   │   ├── constants.go     # Consumer group
│   │   │   ├── service.go       # org_domains persistence
│   │   │   └── consumer.go      # Consumes domain_discovery_results
│   │   └── port_ingestion/      # Port ingestion slice
│   │       ├── constants.go     # Consumer group
│   │       ├── service.go       # attack_surface + org_attack_surface persistence
│   │       └── consumer.go      # Consumes ip_discovery_results
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
│       ├── domain_discovery/   # Shodan domain discovery
│       │   ├── constants.go    # Consumer group name only
│       │   ├── service.go      # Discovery logic
│       │   ├── consumer.go     # Redis consumer
│       │   └── shodan/         # Shodan-specific client
│       │       └── client.go   # Shodan API client
│       └── port_discovery/     # Port scanner
│           ├── constants.go    # Consumer group + common ports array
│           ├── service.go      # Port scanning logic
│           ├── consumer.go     # Redis consumer
│           └── scanner/        # Simple TCP scanner
│               └── scanner.go  # TCP connect with 2s timeout
├── ops/                   # Docker and deployment files
│   ├── Dockerfile.active-recon
│   ├── Dockerfile.passive-recon
│   ├── Dockerfile.domain-discovery
│   ├── Dockerfile.port-discovery
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

1. **Discovery services** (in `internal/discoveries/`) consume jobs from Redis streams:
   - Domain discovery: consumes from `domain_discovery_queue`
   - Port discovery: consumes from `ip_discovery_queue`
2. Discovery services MUST validate `org_id` is present - skip jobs without it
3. Discovery services perform scanning/discovery logic (NO MongoDB access)
4. Discovery services publish findings to Redis result streams with `org_id` and `source`
5. **Ingestion service** (in `internal/ingestion/`) is the ONLY service that writes to MongoDB
6. Ingestion service uses **vertical slice architecture** with concurrent consumers:
   - `domain_ingestion` - processes domain discoveries → `org_domains` collection
   - `port_ingestion` - processes port discoveries → `attack_surface` + `org_attack_surface` collections
7. Each ingestion slice MUST validate `source` is present - skip findings without it
8. **Normalized database design:**
   - Assets stored in `attack_surface` (NO org_id in this collection)
   - Org-to-asset relationships stored in `org_attack_surface` (links orgs to assets)

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

DOMAIN DISCOVERY FLOW:
1. Job Published to domain_discovery_queue (with org_id)
   └─→ Consumed by domain discovery service

2. Domain Discovery Service (Shodan)
   ├─→ Finds subdomains and resolves IPs
   └─→ Publishes to domain_discovery_results (source="shodan")

3. Domain Ingestion Consumer
   └─→ Persists to org_domains collection
       ├─→ Stores domains with IP resolution history
       └─→ Tracks IP changes over time

PORT DISCOVERY FLOW:
1. Job Published to ip_discovery_queue (with org_id)
   └─→ Consumed by port discovery service

2. Port Discovery Service
   ├─→ Scans 23 common ports (TCP connect, 2s timeout)
   └─→ Publishes to ip_discovery_results (source="port_discovery")

3. Port Ingestion Consumer
   └─→ Persists to TWO collections:
       ├─→ attack_surface (assets without org_id)
       └─→ org_attack_surface (org-to-asset relationships)

INGESTION SERVICE ARCHITECTURE:
├─→ Orchestrator starts both consumers concurrently
├─→ domain_ingestion: consumes domain_discovery_results
└─→ port_ingestion: consumes ip_discovery_results
```

### Model Ownership Rules

**Models belong in `internal/shared/` when used by multiple services:**

✅ **Put in `internal/shared/models.go`:**
- Models used by 2+ services
- Shared job formats:
  - `DiscoveryJob` (domain discovery jobs)
  - `IPDiscoveryJob` (port discovery jobs)
- Shared finding formats:
  - `DiscoveryFinding` (domain discovery findings)
  - `IPDiscoveryFinding` (port discovery findings)
- Shared asset models:
  - `AttackSurfaceAsset` (port/service assets)
  - `OrgAttackSurface` (org-to-asset relationships)
  - `OrgDomain` (domain assets with IP history)
- Common data structures for inter-service communication

✅ **Put in `internal/shared/constants.go`:**
- Shared stream names:
  - `StreamDomainDiscoveryQueue`, `StreamDomainDiscoveryResults`
  - `StreamIPDiscoveryQueue`, `StreamIPDiscoveryResults`
- Shared collection names:
  - `CollectionAttackSurface`, `CollectionOrgAttackSurface`, `CollectionOrgDomains`
- Protocol/status constants used by multiple services
- Org asset status constants (confirmed, pending, dismissed)
- Target type constants

✅ **Put in `internal/discoveries/[service_name]/`:**
- Models used ONLY by that discovery service
- Service-specific business logic types
- Constants specific to that service (e.g., consumer group names, common ports array)

✅ **Put in `internal/ingestion/[slice_name]/`:**
- Slice-specific constants (consumer group names)
- NO models needed (uses shared models)

❌ **DO NOT put in shared:**
- Models used by only one service
- Service-specific domain logic

**Rule of thumb:** *If a model or constant is used by 2+ services, put it in `shared/`. Otherwise, keep it in the service directory.*

### Discovery Service Architecture

Discovery services use a **parallel consumer group pattern** where multiple independent services listen to the same input stream with different consumer groups, then publish to a shared output stream:

```
Input Stream: domain_discovery_queue
    ↓
    ├─→ Consumer Group: shodan_subdomain_service  → Shodan Discovery Service
    ├─→ Consumer Group: nmap_discovery_service    → Nmap Discovery Service (future)
    └─→ Consumer Group: masscan_discovery_service → Masscan Discovery Service (future)
        ↓
        All publish findings to: domain_discovery_results
        ↓
    Ingestion Service → MongoDB (org_domains collection for Shodan only)
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
1. Publisher sends job to `domain_discovery_queue` stream (MUST include `org_id`)
2. **All** discovery services receive the same job (different consumer groups)
3. Each service validates `org_id` is present (skip if missing)
4. Each service processes the job with its own tool (Shodan, Nmap, etc.)
5. Each service publishes findings to `domain_discovery_results` stream with `org_id` and `source` field
6. Ingestion service consumes from `domain_discovery_results`
7. Ingestion service validates `source` is present (skip if missing)
8. Ingestion service currently only processes Shodan domain discoveries:
   - Shodan domains (with IP, no port) → `org_domains` with IP resolution history
   - Non-Shodan findings → skipped (logged at debug level)

## Common Commands

### Building Services
```bash
make build                      # Build all services
make build-passive              # Build passive-recon only
make build-active               # Build active-recon only
make build-domain-discovery     # Build domain-discovery only
make build-port-discovery       # Build port-discovery only
make build-ingestion            # Build ingestion only
```

### Running Locally
```bash
make run-passive                # Run passive-recon service
make run-active                 # Run active-recon service
make run-domain-discovery       # Run domain-discovery service
make run-port-discovery         # Run port-discovery service
make run-ingestion              # Run ingestion service (both consumers)
```

### Docker Operations
```bash
make docker-up                         # Start all services
make docker-down                       # Stop all services
make docker-scale-passive N=4          # Scale passive workers to 4
make docker-scale-active N=3           # Scale active workers to 3
make docker-scale-domain-discovery N=2 # Scale domain-discovery workers to 2
make docker-scale-port-discovery N=5   # Scale port-discovery workers to 5
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
       // Stream names are in shared.StreamDomainDiscoveryQueue and shared.StreamDomainDiscoveryResults
       GroupNmapDiscovery = "nmap_discovery_service"
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
       // 2. For each discovered port/service, publish finding to domain_discovery_results
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
           StreamName:    shared.StreamDomainDiscoveryQueue,
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
- ✅ Use `shared.StreamDomainDiscoveryQueue` (input stream)
- ✅ Use `shared.StreamDomainDiscoveryResults` (output stream)
- ✅ Use unique consumer group per tool (e.g., `nmap_discovery_service`)
- ✅ Use `shared.DiscoveryJob` for input
- ✅ Use `shared.DiscoveryFinding` for output
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
- `models.go` - Models used by 2+ services (DiscoveryJob, DiscoveryFinding, AttackSurfaceAsset, OrgDomain, ResolutionHistory)
- `constants.go` - Constants used by 2+ services (streams, collections, protocols, statuses)

### Ingestion Service (`internal/ingestion/`)
- `constants.go` - Consumer group name for ingestion service
- `service.go` - MongoDB persistence logic with dual routing:
  - `processOrgDomain()` - Stores Shodan domains in `org_domains` with IP resolution history
  - `processAttackSurface()` - Stores port-based findings in `attack_surface`
  - Source validation (skip findings without `source` field)
- `consumer.go` - Redis consumer for domain_discovery_results stream

### Discovery Service Pattern (`internal/discoveries/[service_name]/`)
Each discovery service is self-contained:
```
internal/discoveries/[service_name]/
├── constants.go   # Consumer group name
├── service.go     # Discovery logic, publishes findings to Redis
├── consumer.go    # Redis consumer, reads jobs from domain_discovery_queue
├── models.go      # Optional: service-specific models
└── [tool]/        # Tool-specific implementation (client, API wrappers, etc.)
    └── client.go
```

### Shared Models

**DiscoveryJob** - Common job format for all discovery services (input):
```go
type DiscoveryJob struct {
    TraceID  string                 // Request tracing
    OrgID    string                 // REQUIRED: organization GUID (validated by consumers)
    ParentID *string                // Parent asset ID (for recursive discovery)
    Host     string                 // Domain or IP to discover
    Port     *int                   // Optional: specific port to scan
    Protocol *string                // Optional: tcp, udp, sctp, icmp
    Metadata map[string]interface{} // Provider-specific metadata
    Created  time.Time
}
```

**⚠️ IMPORTANT:** Discovery consumers MUST validate `org_id` is present and skip jobs without it.

**DiscoveryFinding** - Common finding format published by all discovery services (output):
```go
type DiscoveryFinding struct {
    TraceID   string                 // Request tracing
    OrgID     string                 // REQUIRED: organization GUID (passed from job)
    Source    string                 // REQUIRED: "shodan", "nmap", "masscan", etc. (validated by ingestion)
    ParentID  *string                // Parent asset ID
    Host      string                 // Domain or IP
    IP        *string                // Resolved IP address (Shodan includes this)
    Port      *int                   // Optional port number
    Protocol  *string                // tcp, udp, sctp, icmp (nil for non-port assets)
    Status    string                 // active, inactive, unknown
    Metadata  map[string]interface{} // Source-specific data
    Timestamp time.Time              // When finding was discovered
}
```

**⚠️ IMPORTANT:** Ingestion service MUST validate `source` is present and skip findings without it.

**IPDiscoveryJob** - Job format for port discovery services (input):
```go
type IPDiscoveryJob struct {
    TraceID   string                 // Request tracing
    OrgID     string                 // REQUIRED: organization GUID (validated by consumers)
    ParentID  *string                // Parent asset ID
    IP        string                 // Target IP address
    PortRange *string                // Optional: "1-1000" or "80,443,22"
    Metadata  map[string]interface{} // Provider-specific metadata
    Created   time.Time
}
```

**IPDiscoveryFinding** - Finding format published by port discovery services (output):
```go
type IPDiscoveryFinding struct {
    TraceID   string                 // Request tracing
    OrgID     string                 // REQUIRED: organization GUID (passed from job)
    Source    string                 // REQUIRED: "port_discovery", etc. (validated by ingestion)
    ParentID  *string                // Parent asset ID
    IP        string                 // Target IP
    Port      int                    // Discovered port number
    Protocol  string                 // tcp, udp
    Status    string                 // active, inactive
    Metadata  map[string]interface{} // Source-specific data (e.g., banner)
    Timestamp time.Time              // When finding was discovered
}
```

**OrgDomain** - Domain model with IP resolution history (MongoDB `org_domains` collection):
```go
type OrgDomain struct {
    ID                string              // UUID
    OrgID             string              // Organization GUID
    Domain            string              // Domain name (e.g., "api.example.com")
    Source            string              // Discovery source ("shodan", etc.)
    ResolutionHistory []ResolutionHistory // IP resolution history over time
}

type ResolutionHistory struct {
    IP               string     // IP address
    AttackSurfaceID  *string    // Optional: links to AttackSurfaceAsset
    ResolvedFrom     time.Time  // When this IP resolution started
    ResolvedUntil    *time.Time // When it ended (nil = currently active)
}
```

**How IP Resolution History Works:**
- When a domain is first discovered, a new `OrgDomain` is created with initial IP
- When the same domain is scanned again:
  - **IP unchanged:** No update (skip)
  - **IP changed:** Close previous resolution (set `resolved_until`), add new resolution
- Only the most recent resolution has `resolved_until = nil` (currently active)
- This tracks domain hijacking, infrastructure changes, and CDN switches over time

**AttackSurfaceAsset** - Port/service model (MongoDB `attack_surface` collection):
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
    Metadata  map[string]interface{} // Source-specific data (e.g., banner, service name)
    // NOTE: NO org_id in this collection - use OrgAttackSurface for org relationships
}
```

**OrgAttackSurface** - Links organizations to attack surface assets (MongoDB `org_attack_surface` collection):
```go
type OrgAttackSurface struct {
    ID              string    // UUID
    AttackSurfaceID string    // References AttackSurfaceAsset._id
    OrgID           string    // Organization GUID
    Status          string    // "confirmed", "pending", "dismissed"
    AssignedAt      time.Time // When the asset was assigned to this org
    Source          string    // Discovery source that found this asset ("port_discovery", etc.)
}
```

**Key Design Decisions:**
- ✅ **Normalized database design:**
  - `attack_surface` - Stores assets WITHOUT org_id (normalized, deduplicated)
  - `org_attack_surface` - Stores org-to-asset relationships (many-to-many)
  - `org_domains` - Shodan domain discoveries with IP history (includes org_id)
- ✅ **Flexible relationships** - Same asset can belong to multiple organizations
- ✅ **Clean separation** - Assets are org-agnostic, relationships tracked separately
- ✅ **Status tracking** - Each org can have different status for the same asset
- ✅ **Protocol-aware** - `192.168.1.1:53/tcp` ≠ `192.168.1.1:53/udp`
- ✅ **Asset deduplication** - Unique by (host + port + protocol), handled by ingestion service
- ✅ **Source tracking** - Both finding source and org-asset link source are tracked
- ✅ **IP history** - Track domain-to-IP changes over time for security monitoring
- ✅ **Separation of concerns** - Discovery services publish, ingestion service persists

### Shared Constants

**Stream Names:**
- `shared.StreamDomainDiscoveryQueue = "domain_discovery_queue"` - Input stream for domain discovery jobs (requires `org_id`)
- `shared.StreamDomainDiscoveryResults = "domain_discovery_results"` - Output stream for domain discovery findings (requires `source`)
- `shared.StreamIPDiscoveryQueue = "ip_discovery_queue"` - Input stream for IP port discovery jobs (requires `org_id`)
- `shared.StreamIPDiscoveryResults = "ip_discovery_results"` - Output stream for IP port discovery findings (requires `source`)

**Collection Names:**
- `shared.CollectionAttackSurface = "attack_surface"` - Port-based assets (NO org_id stored here)
- `shared.CollectionOrgAttackSurface = "org_attack_surface"` - Org-to-asset relationships
- `shared.CollectionOrgDomains = "org_domains"` - Shodan domain discoveries with IP history

**Protocols:**
- `shared.ProtocolTCP`, `ProtocolUDP`, `ProtocolSCTP`, `ProtocolICMP`

**Target Types:**
- `shared.TargetTypeDomain`, `TargetTypeIP`, `TargetTypeCIDR`

**Asset Status:**
- `shared.AssetStatusActive`, `AssetStatusInactive`, `AssetStatusUnknown`

**Org Asset Status:**
- `shared.OrgAssetStatusConfirmed` - Asset confirmed to belong to org
- `shared.OrgAssetStatusPending` - Asset pending verification
- `shared.OrgAssetStatusDismissed` - Asset dismissed/not relevant to org

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

### Domain Discovery (Shodan)

To trigger domain discovery:

```bash
# ✅ VALID: Job with org_id (will be processed)
redis-cli XADD domain_discovery_queue * data '{
  "trace_id": "trace-123",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "example.com",
  "created": "2025-10-15T10:00:00Z"
}'

# Result:
# 1. Domain discovery service finds subdomains and resolves IPs
# 2. Findings published to domain_discovery_results with org_id and source="shodan"
# 3. Domain ingestion consumer stores in org_domains collection with IP resolution history
```

### Port Discovery (TCP Scanner)

To trigger port discovery:

```bash
# ✅ VALID: Job with org_id (will be processed)
redis-cli XADD ip_discovery_queue * data '{
  "trace_id": "trace-456",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip": "8.8.8.8",
  "created": "2025-10-15T10:00:00Z"
}'

# Result:
# 1. Port discovery service scans 23 common ports (TCP connect, 2s timeout)
# 2. For each open port, finding published to ip_discovery_results with source="port_discovery"
# 3. Port ingestion consumer stores in:
#    - attack_surface collection (asset without org_id)
#    - org_attack_surface collection (org-to-asset link with status="confirmed")
```

**❌ INVALID: Job without org_id (will be skipped):**
```bash
redis-cli XADD ip_discovery_queue * data '{
  "trace_id": "trace-789",
  "ip": "8.8.8.8",
  "created": "2025-10-15T10:00:00Z"
}'
# This job will be skipped by port discovery consumer
```

**⚠️ IMPORTANT:** All jobs MUST include `org_id` or they will be skipped by consumers.

### Querying Results

**Query attack surface assets for an organization:**
```javascript
// Join org_attack_surface with attack_surface
db.org_attack_surface.aggregate([
  { $match: { org_id: "550e8400-e29b-41d4-a716-446655440000" } },
  { $lookup: {
      from: "attack_surface",
      localField: "attacksurface_id",
      foreignField: "_id",
      as: "asset"
  }},
  { $unwind: "$asset" }
])
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
3. Verify: Publish test job to `domain_discovery_queue`, check MongoDB for results
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
- **Organization-scoped** - All jobs require `org_id` (GUID), consumers skip jobs without it
- **Two discovery flows:**
  - **Domain discovery:** `domain_discovery_queue` → `domain_discovery_results` → `org_domains`
  - **Port discovery:** `ip_discovery_queue` → `ip_discovery_results` → `attack_surface` + `org_attack_surface`
- **Independent scaling** - Scale each discovery tool independently (e.g., 5 domain workers, 10 port workers)
- **Unique consumer groups** - Each tool has its own group:
  - Domain: `shodan_subdomain_service`
  - Port: `port_discovery_service`
- **Shared models** - All use appropriate shared job/finding models
- **Source validation** - Ingestion service requires `source` field, skips findings without it
- **Vertical slice ingestion** - Each ingestion type runs concurrently:
  - **domain_ingestion** - Shodan domains → `org_domains` with IP resolution history
  - **port_ingestion** - Port scans → `attack_surface` + `org_attack_surface` (normalized design)
- **IP resolution tracking** - Domain discovery resolves IPs, ingestion tracks changes over time
- **Source attribution** - Use `source` field to identify which tool discovered the asset
- **Normalized org relationships** - Port assets stored without org_id, relationships in separate collection

### Example: Shodan Discovery Service
```
internal/discoveries/shodan_discovery/
├── constants.go      # GroupShodanSubdomainService only
├── service.go        # Uses shared.DiscoveryJob, publishes shared.DiscoveryFinding
├── consumer.go       # Listens to shared.StreamDomainDiscoveryQueue with GroupShodanSubdomainService
└── shodan/
    └── client.go     # Shodan API client implementation
```

**Domain Discovery Flow:**
1. Job published to `domain_discovery_queue` (with `org_id`)
2. Domain discovery service validates `org_id` is present (skips if missing)
3. Domain discovery service finds subdomains using Shodan API
4. For each domain (root + subdomains):
   - Resolves domain to IP address
   - Publishes finding to `domain_discovery_results` with `org_id`, `source="shodan"`, and `ip`
5. Domain ingestion consumer validates `source` is present (skips if missing)
6. For Shodan findings (with IP, no port):
   - Stores in `org_domains` collection
   - Tracks IP resolution history
   - If IP changed: closes old resolution, adds new one

### Example: Port Discovery Service
```
internal/discoveries/port_discovery/
├── constants.go      # GroupPortDiscovery + CommonPorts array (23 ports)
├── service.go        # Uses shared.IPDiscoveryJob, publishes shared.IPDiscoveryFinding
├── consumer.go       # Listens to shared.StreamIPDiscoveryQueue with GroupPortDiscovery
└── scanner/
    └── scanner.go    # Simple TCP connect scanner with 2s timeout
```

**Port Discovery Flow:**
1. Job published to `ip_discovery_queue` (with `org_id`)
2. Port discovery service validates `org_id` is present (skips if missing)
3. Port discovery service scans 23 common ports (TCP connect, 2s timeout, concurrent)
4. For each open port:
   - Attempts to grab service banner (500ms timeout)
   - Publishes finding to `ip_discovery_results` with `org_id`, `source="port_discovery"`, port, protocol
5. Port ingestion consumer validates `source` is present (skips if missing)
6. For port findings:
   - Stores asset in `attack_surface` collection (deduped by IP + port + protocol, NO org_id)
   - Creates link in `org_attack_surface` collection (org_id + asset_id + status="confirmed")
   - If asset exists: updates `last_seen` and merges metadata
