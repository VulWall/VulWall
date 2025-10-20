# VulWall NightWatch

VulWall NightWatch is an **asset discovery platform** built with a vertically-sliced Go monorepo architecture. The platform discovers and tracks security assets (domains, subdomains, IPs, ports) across organizations using a distributed discovery + ingestion pipeline.

## Architecture

### Discovery + Ingestion Pattern

NightWatch uses a **separation of concerns** architecture where:
- **Discovery services** find assets and publish findings to Redis streams (NO MongoDB access)
- **Ingestion service** is the single source of truth for MongoDB persistence (vertical slice architecture)

```
┌──────────────────────────────────────────────────────────────────┐
│                    NightWatch Architecture                        │
└──────────────────────────────────────────────────────────────────┘

DOMAIN DISCOVERY:
Job → domain_discovery_queue → Domain Discovery Service (Shodan)
  ↓
Findings → domain_discovery_results → Domain Ingestion
  ↓
MongoDB: discoveries (domain, subdomain, ip) + org_assets

PORT DISCOVERY:
Job → ip_discovery_queue → Port Discovery Service (TCP Scanner)
  ↓
Findings → ip_discovery_results → Port Ingestion
  ↓
MongoDB: discoveries (port) + org_assets
```

### Project Structure

```
VulWall.NightWatch/
├── cmd/                          # Entry points for each service
│   ├── domain-discovery/         # Shodan subdomain discovery
│   ├── port-discovery/           # TCP port scanner
│   ├── ingestion/                # MongoDB persistence orchestrator
│   ├── active-recon/             # Active reconnaissance (future)
│   └── passive-recon/            # Passive reconnaissance (future)
├── internal/
│   ├── core/                     # Shared infrastructure
│   │   ├── bootstrap/            # Common service initialization
│   │   ├── config/               # Configuration loader
│   │   ├── logger/               # Zap logger setup
│   │   ├── mongox/               # MongoDB connection + indexes
│   │   └── redisx/               # Redis client + consumer groups
│   ├── shared/                   # Cross-cutting concerns
│   │   ├── models.go             # Shared models (DiscoveryJob, Discovery, etc.)
│   │   └── constants.go          # Shared constants (streams, collections)
│   ├── discoveries/              # Discovery services (NO MongoDB)
│   │   ├── domain_discovery/     # Shodan subdomain discovery
│   │   │   ├── constants.go      # Consumer group name
│   │   │   ├── service.go        # Discovery logic
│   │   │   ├── consumer.go       # Redis consumer
│   │   │   └── shodan/           # Shodan API client
│   │   ├── port_discovery/       # Port scanner
│   │   │   ├── constants.go      # Consumer group + common ports
│   │   │   ├── service.go        # Port scanning logic
│   │   │   ├── consumer.go       # Redis consumer
│   │   │   └── scanner/          # TCP connect scanner
│   │   ├── active_recon/         # Active recon (planned)
│   │   └── passive_recon/        # Passive recon (planned)
│   └── ingestion/                # Ingestion service (vertical slices)
│       ├── orchestrator.go       # Runs all consumers concurrently
│       ├── domain_ingestion/     # Domain/subdomain/IP persistence
│       │   ├── constants.go
│       │   ├── service.go        # discoveries + org_assets persistence
│       │   └── consumer.go
│       └── port_ingestion/       # Port persistence
│           ├── constants.go
│           ├── service.go        # discoveries + org_assets persistence
│           └── consumer.go
├── ops/                          # Docker and deployment files
│   ├── Dockerfile.domain-discovery
│   ├── Dockerfile.port-discovery
│   ├── Dockerfile.ingestion
│   └── docker-compose.yml
├── bin/                          # Compiled binaries (gitignored)
├── .env.example
├── Makefile
└── go.mod
```

### Key Architectural Principles

- **Organization-scoped**: All jobs require `org_id` (GUID) - consumers skip jobs without it
- **Unified asset storage**: ALL assets (domains, subdomains, IPs, ports) in single `discoveries` collection
- **Type discrimination**: Uses `asset_type` field to distinguish 4 asset types
- **Normalized design**: Assets stored WITHOUT org_id, relationships in separate `org_assets` collection
- **Hierarchical relationships**: Domain → Subdomain → IP → Port via `parent_id` fields
- **Two status fields**:
  - `discovery.status` = technical state (active/inactive)
  - `org_assets.status` = organizational state (confirmed/pending/dismissed)
- **History tracking**:
  - Domains/subdomains: IP resolution history
  - Ports: Service change history
- **Source attribution**: Every asset tracks its discovery source

## Getting Started

### Prerequisites

- Go 1.23 or higher
- Docker and Docker Compose (for containerized deployment)
- **Cloud Redis** (Redis Cloud, Upstash, AWS ElastiCache, etc.)
- **Cloud MongoDB** (MongoDB Atlas, AWS DocumentDB, etc.)
- **Shodan API Key** (for domain discovery service)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd VulWall.NightWatch
```

2. Copy the environment file and configure your cloud credentials:
```bash
cp .env.example .env
# Edit .env with your cloud Redis, MongoDB, and Shodan API credentials
```

3. Install dependencies:
```bash
make deps
```

### Running Locally

#### Option 1: Using Docker Compose (Recommended)

Start all services:
```bash
make docker-up
```

Scale specific workers:
```bash
make docker-scale-domain-discovery N=2
make docker-scale-port-discovery N=5
make docker-scale-ingestion N=3
```

View logs:
```bash
make docker-logs
```

Stop all services:
```bash
make docker-down
```

#### Option 2: Running Individually (Local Development)

You need to run at least 2 services for the pipeline to work:

**Terminal 1 - Domain Discovery:**
```bash
make run-domain-discovery
```

**Terminal 2 - Port Discovery:**
```bash
make run-port-discovery
```

**Terminal 3 - Ingestion (REQUIRED):**
```bash
make run-ingestion
```

### Building

Build all services:
```bash
make build
```

Build specific services:
```bash
make build-domain-discovery
make build-port-discovery
make build-ingestion
```

The binaries will be created in the `bin/` directory.

## Usage

### Discovery Job Formats

#### Domain Discovery Job

Triggers subdomain discovery via Shodan:

```json
{
  "trace_id": "trace-123",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "example.com",
  "created": "2025-10-20T10:00:00Z"
}
```

**Required fields:**
- `org_id` - Organization GUID (jobs without this are skipped)
- `host` - Domain to discover

#### Port Discovery Job

Triggers port scanning on an IP:

```json
{
  "trace_id": "trace-456",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip": "8.8.8.8",
  "created": "2025-10-20T10:00:00Z"
}
```

**Required fields:**
- `org_id` - Organization GUID (jobs without this are skipped)
- `ip` - IP address to scan

### Publishing Jobs to Redis

#### Trigger Domain Discovery

```bash
redis-cli XADD domain_discovery_queue * data '{
  "trace_id": "test-001",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "host": "example.com",
  "created": "2025-10-20T15:00:00Z"
}'
```

**What happens:**
1. Domain discovery service finds subdomains using Shodan
2. For each domain/subdomain, resolves IP address
3. Publishes findings to `domain_discovery_results`
4. Domain ingestion consumer stores in MongoDB:
   - Creates domain/subdomain records in `discoveries` (asset_type: "domain" or "subdomain")
   - Creates IP records in `discoveries` (asset_type: "ip")
   - Creates `org_assets` links for organization relationships
   - Tracks IP resolution history
   - **Automatically triggers port scanning for new IPs**

#### Trigger Port Discovery

```bash
redis-cli XADD ip_discovery_queue * data '{
  "trace_id": "test-002",
  "org_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip": "8.8.8.8",
  "created": "2025-10-20T15:00:00Z"
}'
```

**What happens:**
1. Port discovery service scans 23 common ports (TCP connect, 2s timeout)
2. For each open port, publishes finding to `ip_discovery_results`
3. Port ingestion consumer stores in MongoDB:
   - Ensures IP record exists in `discoveries`
   - Creates port records in `discoveries` (asset_type: "port")
   - Tracks service changes (banner, service_name, product, version)
   - Creates `org_assets` links for both IP and port

### Querying Results

#### Find All Assets for an Organization

```javascript
// MongoDB aggregation
db.org_assets.aggregate([
  { $match: { org_id: "550e8400-e29b-41d4-a716-446655440000" } },
  { $lookup: {
      from: "discoveries",
      localField: "asset_id",
      foreignField: "_id",
      as: "discovery"
  }},
  { $unwind: "$discovery" }
])
```

#### Find All Ports for an Organization

```javascript
db.org_assets.aggregate([
  { $match: { org_id: "550e8400-e29b-41d4-a716-446655440000" } },
  { $lookup: {
      from: "discoveries",
      localField: "asset_id",
      foreignField: "_id",
      as: "discovery"
  }},
  { $unwind: "$discovery" },
  { $match: { "discovery.asset_type": "port" } }
])
```

#### Query Domain Hierarchy

```javascript
// Find all subdomains of a domain
db.discoveries.find({
  asset_type: "subdomain",
  parent_id: "domain-uuid-here"
})

// Find all IPs resolved from a domain/subdomain
db.discoveries.find({
  asset_type: "ip",
  parent_id: "domain-or-subdomain-uuid-here"
})

// Find all ports on an IP
db.discoveries.find({
  asset_type: "port",
  parent_id: "ip-uuid-here"
})
```

## Configuration

Configuration is loaded from environment variables or `.env` file:

| Variable | Description | Example |
|----------|-------------|---------|
| `REDIS_ADDR` | Cloud Redis endpoint | `redis-12345.cloud.redislabs.com:12345` |
| `REDIS_PASSWORD` | Redis authentication password | `your-redis-password` |
| `REDIS_DB` | Redis database number | `0` |
| `MONGO_URI` | MongoDB Atlas/Cloud connection string | `mongodb+srv://user:pass@cluster.mongodb.net/` |
| `MONGO_DB` | MongoDB database name | `vulwall` |
| `SHODAN_API_KEY` | Shodan API key for subdomain discovery | `your-shodan-api-key` |
| `ENVIRONMENT` | Environment (development/production) | `development` |

## Services

### 1. Domain Discovery Service

**Purpose**: Discovers subdomains and resolves IPs using Shodan API

**Stream**: Consumes from `domain_discovery_queue` (consumer group: `shodan_subdomain_service`)

**Output**: Publishes to `domain_discovery_results`

**Scaling**: `make docker-scale-domain-discovery N=2`

### 2. Port Discovery Service

**Purpose**: Scans 23 common TCP ports on target IPs

**Stream**: Consumes from `ip_discovery_queue` (consumer group: `port_discovery_service`)

**Output**: Publishes to `ip_discovery_results`

**Scaling**: `make docker-scale-port-discovery N=5`

### 3. Ingestion Service

**Purpose**: Single source of truth for MongoDB persistence (runs 2 concurrent consumers)

**Architecture**: Vertical slice with concurrent consumers:
- **domain_ingestion** - Processes domains, subdomains, and IPs
- **port_ingestion** - Processes ports

**Scaling**: `make docker-scale-ingestion N=3`

### 4. Active Recon Service (Planned)

**Purpose**: Active reconnaissance scanning

**Status**: 🚧 Infrastructure ready, implementation pending

### 5. Passive Recon Service (Planned)

**Purpose**: Passive reconnaissance scanning

**Status**: 🚧 Infrastructure ready, implementation pending

## Redis Streams

### Streams and Consumer Groups

| Stream | Direction | Consumer Groups | Purpose |
|--------|-----------|-----------------|---------|
| `domain_discovery_queue` | Input | `shodan_subdomain_service` | Domain discovery jobs |
| `domain_discovery_results` | Output | `domain_ingestion_group` | Domain discovery findings |
| `ip_discovery_queue` | Input | `port_discovery_service` | IP port discovery jobs |
| `ip_discovery_results` | Output | `port_ingestion_group` | IP port discovery findings |

### Monitoring Streams

```bash
# View pending messages
redis-cli XPENDING domain_discovery_queue shodan_subdomain_service

# View stream length
redis-cli XLEN domain_discovery_queue

# View recent messages
redis-cli XRANGE domain_discovery_results - + COUNT 10
```

## MongoDB Collections

### `discoveries` Collection

Global asset registry storing ALL discovered assets (NO org_id):

**Asset Types:**
- `domain` - Root domains (e.g., "example.com")
- `subdomain` - Subdomains (e.g., "api.example.com")
- `ip` - IP addresses
- `port` - Open ports with service information

**Key Fields:**
- `_id` - UUID
- `asset_type` - Type discrimination ("domain", "subdomain", "ip", "port")
- `source` - Discovery source ("shodan", "port_discovery", etc.)
- `status` - Technical state (active, inactive, unknown)
- `parent_id` - Parent asset ID (for hierarchy)
- `resolution_history` - IP resolution changes (domains/subdomains only)
- `previous_services` - Service change history (ports only)

**Indexes:**
- `idx_asset_type_domain` - Find domains by name
- `idx_asset_type_subdomain` - Find subdomains by name
- `idx_asset_type_ip` - Find IPs
- `idx_asset_type_ip_port_protocol` - Find ports (compound)
- `idx_parent_id_asset_type` - Find children by parent
- `idx_status_asset_type` - Filter by status
- `idx_last_seen` - Time-based queries
- `idx_source_asset_type` - Filter by source

### `org_assets` Collection

Org-to-asset relationship links (many-to-many):

**Key Fields:**
- `_id` - UUID
- `org_id` - Organization GUID
- `asset_id` - References `discoveries._id`
- `status` - Organizational state (confirmed, pending, dismissed)
- `assigned_at` - When asset was assigned to org

**Indexes:**
- `idx_org_id_asset_id` - UNIQUE, prevents duplicate links
- `idx_org_id_status` - Find all assets for an org
- `idx_asset_id` - Find all orgs that have a specific asset

## Development

### Adding a New Discovery Service

See [CLAUDE.md](CLAUDE.md) for detailed instructions on adding new discovery tools (e.g., nmap, masscan).

**Quick overview:**
1. Create service directory in `internal/discoveries/`
2. Implement service, consumer, and tool-specific client
3. Use shared models (`DiscoveryJob`, `DiscoveryFinding`)
4. Publish findings with `source` field
5. NO MongoDB access (ingestion service handles persistence)

### Testing

Run all tests:
```bash
make test
```

Run tests with coverage:
```bash
make test-coverage
```

### Code Quality

Format code:
```bash
make fmt
```

Run linter:
```bash
make lint
```

Run static analysis:
```bash
make vet
```

## Deployment

### Docker Production Build

All Docker files are located in the `ops/` directory:

```bash
# Build optimized production images
make docker-build

# Deploy with specific replicas
make docker-up
make docker-scale-domain-discovery N=2
make docker-scale-port-discovery N=5
make docker-scale-ingestion N=3
```

Or use docker-compose directly:
```bash
docker-compose -f ops/docker-compose.yml build
docker-compose -f ops/docker-compose.yml up -d \
  --scale domain-discovery=2 \
  --scale port-discovery=5 \
  --scale ingestion=3
```

### Kubernetes (Planned)

Each service can be deployed as a separate Kubernetes Deployment with:
- HorizontalPodAutoscaler for auto-scaling
- ConfigMaps for configuration
- Secrets for sensitive data

## Roadmap

**Discovery Services:**
- [x] Domain discovery (Shodan)
- [x] Port discovery (TCP scanner)
- [ ] Subdomain enumeration (amass, subfinder)
- [ ] Service detection (nmap service scan)
- [ ] Vulnerability scanning (nuclei, nessus)
- [ ] Screenshot capture (aquatone, gowitness)

**Platform Features:**
- [x] Unified asset storage with type discrimination
- [x] Org-to-asset relationship tracking
- [x] IP resolution history tracking
- [x] Service change history tracking
- [x] MongoDB indexes for performance
- [ ] REST API for job management
- [ ] GraphQL API for asset queries
- [ ] Web UI for asset visualization
- [ ] Asset tagging and categorization
- [ ] Asset risk scoring
- [ ] Notification system (Slack, webhooks)
- [ ] Scheduled discovery jobs
- [ ] Asset expiration and cleanup

**Infrastructure:**
- [x] Bootstrap pattern for service initialization
- [x] Vertical slice ingestion architecture
- [x] Redis streams for job distribution
- [x] MongoDB for asset persistence
- [ ] Prometheus metrics
- [ ] Health check endpoints
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Rate limiting
- [ ] Dead letter queues
- [ ] Kubernetes manifests
- [ ] Helm charts
- [ ] Integration tests
- [ ] Load testing

## Architecture Decisions

For detailed architectural guidance and patterns, see [CLAUDE.md](CLAUDE.md).

**Key decisions:**
- **Discovery + Ingestion separation** - Discovery services focus on finding assets, ingestion service handles all MongoDB writes
- **Vertical slice ingestion** - Each ingestion slice (domain_ingestion, port_ingestion) runs concurrently
- **Type discrimination** - Single `discoveries` collection with `asset_type` field (4 types)
- **Normalized org relationships** - Assets stored without org_id, relationships in separate `org_assets` collection
- **Two status fields** - `discovery.status` (technical) vs `org_assets.status` (organizational)
- **Parallel consumer groups** - Multiple discovery tools can process the same job simultaneously
- **History tracking** - IP resolution changes and service changes tracked over time
- **Go-based indexes** - Indexes created at ingestion service startup (idempotent, no migrations needed)

## License

[Your License Here]

## Contributing

[Contributing Guidelines Here]
