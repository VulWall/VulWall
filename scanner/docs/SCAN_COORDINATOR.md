# Scan Coordinator Service

The Scan Coordinator is a background service that automatically schedules and triggers scans based on organization subscription settings.

## Overview

The coordinator runs every hour (configurable) and:
1. Queries all organizations from the `organizations` collection
2. Checks each organization's `subscription_settings.scan_interval_days`
3. Compares the time since the last scan
4. If enough time has elapsed, creates a new scan and publishes discovery jobs for all verified assets

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Scan Coordinator Flow                          │
└─────────────────────────────────────────────────────────────────┘

Every hour:
1. Query organizations with scan_interval_days > 0
2. For each organization:
   ├─→ Get last scan from scans collection
   ├─→ Calculate days since last scan
   ├─→ If days >= scan_interval_days:
   │   ├─→ Create new Scan record (status=pending, type=scheduled)
   │   ├─→ Query all verified assets for org
   │   └─→ Publish discovery jobs to Redis:
   │       ├─→ Domains/Subdomains → domain_discovery_queue
   │       └─→ IPs → ip_discovery_queue
   └─→ Discovery services process jobs as usual
```

## Database Collections

### Organizations Collection

```javascript
{
  "_id": "org-uuid-123",
  "user_ids": ["user-1", "user-2"],
  "company_name": "Example Corp",
  "industry": "Technology",
  "website": "https://example.com",
  "cert_visible": true,
  "created_at": ISODate("2025-01-01T00:00:00Z"),
  "updated_at": ISODate("2025-01-10T00:00:00Z"),
  "subscription_settings": {
    "scan_interval_days": 7,    // Scan every 7 days
    "max_assets": 1000,          // Maximum assets allowed
  }
}
```

### Scans Collection

```javascript
{
  "_id": "scan-uuid-456",
  "org_id": "org-uuid-123",
  "status": "pending",           // pending, running, completed, failed
  "type": "scheduled",           // scheduled, manual, on_demand
  "triggered_by": "system",      // "system" for automated scans
  "started_at": null,
  "completed_at": null,
  "created_at": ISODate("2025-01-10T12:00:00Z"),
  "updated_at": ISODate("2025-01-10T12:00:00Z"),
  "stats": {
    "total_assets": 0,
    "assets_scanned": 0,
    "new_assets": 0,
    "findings_detected": 0
  }
}
```

## Configuration

The coordinator uses these configuration settings:

- **Scheduler Interval**: How often to check for scans (default: 3600 seconds = 1 hour)
- Can be modified in `internal/scan_coordinator/constants.go`

## Building

```bash
# Build scan-coordinator
make build-scan-coordinator

# Build all services (including scan-coordinator)
make build
```

## Running Locally

```bash
# Run scan-coordinator locally
make run-scan-coordinator

# Or directly with go run
go run ./cmd/scan-coordinator/main.go
```

## Docker Deployment

```bash
# Build Docker image
docker-compose -f ops/scan-coordinator/docker-compose.yml build

# Run scan-coordinator service
docker-compose -f ops/scan-coordinator/docker-compose.yml up -d

# View logs
docker-compose -f ops/scan-coordinator/docker-compose.yml logs -f

# Stop service
docker-compose -f ops/scan-coordinator/docker-compose.yml down
```

## Production Deployment

```bash
# Deploy scan-coordinator to production
make prod-deploy-scan-coordinator

# With custom project/config
make prod-deploy-scan-coordinator PROJECT=vulwall CONFIG=prd

# Stop scan-coordinator
make prod-stop-service SERVICE=scan-coordinator

# Restart scan-coordinator
make prod-restart-service SERVICE=scan-coordinator

# View logs
make prod-logs SERVICE=scan-coordinator OPTS=-f
```

## How It Works

### 1. Scheduler Loop

The scheduler runs on a fixed interval (default: 1 hour):

```go
// Run immediately on startup
runCoordinationCycle()

// Then run every hour
for {
    <-ticker.C
    runCoordinationCycle()
}
```

### 2. Organization Processing

For each organization with `scan_interval_days > 0`:

```go
// Get last scan
lastScan := getLastScan(orgID)

// Calculate days since last scan
daysSinceLastScan := time.Since(lastScan.CreatedAt).Hours() / 24

// Trigger scan if interval elapsed
if daysSinceLastScan >= org.SubscriptionSettings.ScanIntervalDays {
    createScan(org)
}
```

### 3. Scan Triggering

When a scan is triggered:

1. **Create Scan Record**:
   ```go
   scan := Scan{
       ID:          uuid.New(),
       OrgID:       org.ID,
       Status:      "pending",
       Type:        "scheduled",
       TriggeredBy: "system",
       CreatedAt:   time.Now(),
   }
   db.scans.insertOne(scan)
   ```

2. **Get Verified Assets**:
   ```javascript
   db.discoveries.find({
       org_id: "org-123",
       ownership_status: "verified",
       asset_type: { $in: ["domain", "subdomain", "ip"] }
   })
   ```

3. **Publish Discovery Jobs**:
   ```go
   // For domains/subdomains
   redis.XADD("domain_discovery_queue", {
       trace_id: uuid,
       scan_id: scanID,
       org_id: orgID,
       host: asset.Domain,
       created: now
   })

   // For IPs
   redis.XADD("ip_discovery_queue", {
       trace_id: uuid,
       scan_id: scanID,
       org_id: orgID,
       ip: asset.IP,
       created: now
   })
   ```

## Example Usage

### Setting Up an Organization for Automated Scans

```javascript
// Insert organization with scan settings
db.organizations.insertOne({
  _id: "550e8400-e29b-41d4-a716-446655440000",
  user_ids: ["user-123"],
  company_name: "Acme Corporation",
  industry: "Technology",
  website: "https://acme.com",
  cert_visible: true,
  created_at: new Date(),
  updated_at: new Date(),
  subscription_settings: {
    scan_interval_days: 7,      // Scan every 7 days
    max_assets: 5000,
  }
})
```

### Adding Assets to Scan

```javascript
// Add a domain asset
db.discoveries.insertOne({
  _id: "domain-uuid-123",
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  asset_type: "domain",
  source: "manual",
  status: "active",
  ownership_status: "verified",    // Must be verified to be scanned
  discovered_at: new Date(),
  first_seen: new Date(),
  last_seen: new Date(),
  domain: "acme.com",
  resolution_history: [
    {
      ip: "192.168.1.100",
      first_seen: new Date(),
      last_seen: null
    }
  ]
})

// Add an IP asset
db.discoveries.insertOne({
  _id: "ip-uuid-456",
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  asset_type: "ip",
  source: "shodan",
  status: "active",
  ownership_status: "verified",    // Must be verified to be scanned
  discovered_at: new Date(),
  first_seen: new Date(),
  last_seen: new Date(),
  ip: "192.168.1.100",
  parent_id: "domain-uuid-123"
})
```

### Monitoring Scans

```javascript
// View all scans for an organization
db.scans.find({ org_id: "550e8400-e29b-41d4-a716-446655440000" })
  .sort({ created_at: -1 })

// View latest scan
db.scans.findOne(
  { org_id: "550e8400-e29b-41d4-a716-446655440000" },
  { sort: { created_at: -1 } }
)

// Count scans by status
db.scans.aggregate([
  { $match: { org_id: "550e8400-e29b-41d4-a716-446655440000" } },
  { $group: { _id: "$status", count: { $sum: 1 } } }
])

// View scan-triggered discoveries
db.discoveries.find({
  org_id: "550e8400-e29b-41d4-a716-446655440000",
  scan_ids: "scan-uuid-456"
})
```

## Disabling Automated Scans

To disable automated scans for an organization:

```javascript
// Set scan_interval_days to 0
db.organizations.updateOne(
  { _id: "550e8400-e29b-41d4-a716-446655440000" },
  { $set: { "subscription_settings.scan_interval_days": 0 } }
)
```

## Troubleshooting

### Check Coordinator Status

```bash
# View logs
docker logs nightwatch-scan-coordinator -f

# Or with make
make prod-logs SERVICE=scan-coordinator OPTS=-f
```

### Common Issues

1. **No scans being triggered**:
   - Check `scan_interval_days > 0` in organization settings
   - Verify coordinator is running: `docker ps | grep scan-coordinator`
   - Check logs for errors

2. **Scans not processing assets**:
   - Verify assets have `ownership_status: "verified"`
   - Check that discovery services are running
   - Verify Redis connectivity

3. **Too many scans**:
   - Increase `scan_interval_days` in organization settings
   - Check for duplicate organizations in database

## Integration with Existing Services

The scan coordinator integrates seamlessly with existing services:

1. **Discovery Services** consume jobs from Redis streams (no changes needed)
2. **Ingestion Service** persists findings to MongoDB (no changes needed)
3. **Findings Service** tracks security vulnerabilities (no changes needed)

All scan-triggered discoveries and findings include the `scan_id` field for tracking.

## Performance Considerations

- **Scheduler Interval**: Adjust based on organization count (default: 1 hour)
- **Batch Size**: The coordinator processes all organizations in each cycle
- **Resource Usage**: Minimal - only queries MongoDB and publishes to Redis
- **Scaling**: Run only 1 instance (scheduler should not be scaled horizontally)

## Security Considerations

- Only triggers scans for organizations with `scan_interval_days > 0`
- Only scans assets with `ownership_status: "verified"`
- Scans are logged with `triggered_by: "system"` for audit trail
- All discovery jobs include `org_id` for proper scoping
