# VulWall Scanners

VulWall Scanners is a modular, vertically-sliced Go monorepo architecture for security scanning services. Each feature (active recon, passive recon) is a self-contained service that can be built and deployed independently while sharing common infrastructure. Currently focused on infrastructure setup with plans to add vulnerability scanning and report generation.

## Architecture

### Vertical Slice Monolith

```
VulWall.Scanners/
├── cmd/                    # Entry points for each service
│   ├── active-recon/
│   └── passive-recon/
├── internal/
│   ├── core/              # Shared infrastructure
│   │   ├── config/        # Configuration loader
│   │   ├── logger/        # Logging setup
│   │   ├── mongox/        # MongoDB connector
│   │   └── redisx/        # Redis client wrapper
│   ├── shared/            # Domain models and constants
│   └── slices/            # Independent vertical slices
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

**Note**: Currently infrastructure-focused. Additional slices (vuln_scan, report_gen) and external scanning tool integrations will be added as the project evolves.

### Key Benefits

- **Single Codebase**: Unified models, shared infrastructure, single go.mod
- **Independent Scaling**: Each service compiles to its own binary
- **Low Coupling**: Each slice owns its logic and dependencies
- **Easy Local Dev**: Run services individually with `go run`
- **Microservice-Ready**: Deploy as separate containers when needed

## Getting Started

### Prerequisites

- Go 1.23 or higher
- Docker and Docker Compose (for containerized deployment)
- Redis 7+
- MongoDB 7+

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd VulWall.Scanners
```

2. Copy the environment file:
```bash
cp .env.example .env
```

3. Install dependencies:
```bash
make deps
```

### Running Locally

#### Option 1: Using Docker Compose (Recommended)

Start all services with infrastructure:
```bash
make docker-up
```

Scale specific workers:
```bash
make docker-scale-passive N=4
make docker-scale-active N=2
```

View logs:
```bash
make docker-logs
```

Stop all services:
```bash
make docker-down
```

#### Option 2: Running Individually

First, ensure Redis and MongoDB are running locally.

Run passive reconnaissance service:
```bash
make run-passive
```

Run active reconnaissance service:
```bash
make run-active
```

### Building

Build all services:
```bash
make build
```

Build specific service:
```bash
make build-passive
make build-active
```

The binaries will be created in the `bin/` directory.

## Usage

### Scan Job Format

Jobs are published to Redis streams. Example passive recon job:

```json
{
  "scan_id": "scan-123",
  "type": "passive_recon",
  "domain": "example.com",
  "user_id": "user-456",
  "options": {
    "aggressive": false,
    "threads": 10,
    "timeout": 300,
    "tags": ["production"]
  },
  "created": "2025-10-11T10:00:00Z"
}
```

### Publishing Jobs to Redis

```bash
# Publish a passive recon job
redis-cli XADD vulwall:passive_recon * data '{"scan_id":"scan-123","type":"passive_recon","domain":"example.com","user_id":"user-456","options":{"threads":10,"timeout":300},"created":"2025-10-11T10:00:00Z"}'

# Publish an active recon job
redis-cli XADD vulwall:active_recon * data '{"scan_id":"scan-124","type":"active_recon","domain":"example.com","user_id":"user-456","options":{"aggressive":false,"ports":[80,443,22],"threads":5,"timeout":600},"created":"2025-10-11T10:00:00Z"}'
```

### Scan Results

Results are stored in MongoDB in the `scan_results` collection:

```json
{
  "scan_id": "scan-123",
  "type": "passive_recon",
  "status": "completed",
  "results": {
    "subdomains": ["www.example.com", "api.example.com"],
    "dns_records": {
      "A": "192.0.2.1",
      "MX": "mail.example.com"
    },
    "technologies": [
      {
        "name": "Cloudflare",
        "categories": ["CDN", "Security"],
        "confidence": 95
      }
    ]
  },
  "started_at": "2025-10-11T10:00:00Z",
  "completed_at": "2025-10-11T10:00:05Z",
  "duration": 5.2
}
```

## Development

### Project Structure

- **`cmd/`**: Entry points for each service binary
- **`internal/core/`**: Shared infrastructure (Redis, MongoDB, logging, config)
- **`internal/shared/`**: Common models and constants
- **`internal/slices/`**: Vertical slices - each is a bounded context
- **`ops/`**: Docker and deployment configuration files
- **`bin/`**: Compiled binaries (created by build, gitignored)

### Adding a New Service

1. Create new directory in `internal/slices/`:
```bash
mkdir -p internal/slices/new_service
```

2. Create service implementation:
   - `service.go` - Core business logic
   - `consumer.go` - Redis stream consumer
   - `types.go` - Service-specific types (optional)

3. Create entry point in `cmd/`:
```bash
mkdir -p cmd/new-service
```

4. Add constants to `internal/shared/constants.go`:
```go
const (
    StreamNewService = "vulwall:new_service"
    GroupNewService  = "new_service_group"
)
```

5. Create `ops/Dockerfile.new-service` and add service to `ops/docker-compose.yml`

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

## Configuration

Configuration is loaded from environment variables or `.env` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_ADDR` | Redis server address | `localhost:6379` |
| `REDIS_PASSWORD` | Redis password | `` |
| `REDIS_DB` | Redis database number | `0` |
| `MONGO_URI` | MongoDB connection URI | `mongodb://localhost:27017` |
| `MONGO_DB` | MongoDB database name | `vulwall` |
| `SERVICE_NAME` | Service identifier | `vulwall-scanner` |
| `ENVIRONMENT` | Environment (development/production) | `development` |

## Redis Streams

### Streams and Consumer Groups

| Service | Stream Name | Consumer Group | Status |
|---------|-------------|----------------|--------|
| Passive Recon | `vulwall:passive_recon` | `passive_recon_group` | ✅ Implemented |
| Active Recon | `vulwall:active_recon` | `active_recon_group` | ✅ Implemented |
| Vuln Scan | `vulwall:vuln_scan` | `vuln_scan_group` | 🚧 Planned |
| Report Gen | `vulwall:report_gen` | `report_gen_group` | 🚧 Planned |

### Monitoring Streams

```bash
# View pending messages
redis-cli XPENDING vulwall:passive_recon passive_recon_group

# View stream length
redis-cli XLEN vulwall:passive_recon

# View recent messages
redis-cli XRANGE vulwall:passive_recon - + COUNT 10
```

## MongoDB Collections

- **`scan_jobs`**: Scan job metadata
- **`scan_results`**: Scan results and findings

## Deployment

### Docker Production Build

All Docker files are located in the `ops/` directory. The Makefile handles the correct paths automatically.

```bash
# Build optimized production images
make docker-build

# Deploy with specific replicas
make docker-up
make docker-scale-passive N=4
make docker-scale-active N=2
```

Or use docker-compose directly:
```bash
docker-compose -f ops/docker-compose.yml build
docker-compose -f ops/docker-compose.yml up -d --scale passive-recon=4 --scale active-recon=2
```

### Kubernetes (Future)

Each service can be deployed as a separate Kubernetes Deployment with:
- HorizontalPodAutoscaler for auto-scaling
- ConfigMaps for configuration
- Secrets for sensitive data

## Roadmap

- [ ] Implement vulnerability scanning slice
- [ ] Implement report generation slice
- [ ] Add REST API service for job management
- [ ] Add message schema validation
- [ ] Add Prometheus metrics
- [ ] Add health check endpoints
- [ ] Implement retry logic with dead letter queues
- [ ] Add rate limiting
- [ ] Integrate actual scanning tools (nmap, subfinder, nuclei, etc.)
- [ ] Add Kubernetes manifests
- [ ] Add integration tests

## License

[Your License Here]

## Contributing

[Contributing Guidelines Here]
