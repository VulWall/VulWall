package mongox

import (
	"context"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// EnsureIndexes creates all required indexes for the application
// This should be called once at application startup (in ingestion service)
func EnsureIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	logger.Info("Creating MongoDB indexes...")

	// Discoveries collection indexes
	if err := ensureDiscoveriesIndexes(ctx, db, logger); err != nil {
		return err
	}
	if err := ensureScanCoverageIndexes(ctx, db, logger); err != nil {
		return err
	}

	logger.Info("All MongoDB indexes created successfully")
	return nil
}

func ensureDiscoveriesIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	collection := db.Collection(shared.CollectionDiscoveries)

	indexes := []mongo.IndexModel{
		// UNIQUE: org_id + asset_type + domain (prevents duplicate domains per org)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "asset_type", Value: 1},
				{Key: "domain", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_asset_domain").
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypeDomain},
					{Key: "domain", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// UNIQUE: org_id + asset_type + subdomain (prevents duplicate subdomains per org)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "asset_type", Value: 1},
				{Key: "subdomain", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_asset_subdomain").
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypeSubdomain},
					{Key: "subdomain", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// UNIQUE: org_id + asset_type + ip (prevents duplicate IPs per org)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "asset_type", Value: 1},
				{Key: "ip", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_asset_ip").
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypeIP},
					{Key: "ip", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// UNIQUE: org_id + asset_type + ip + port + protocol (prevents duplicate ports per org)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "asset_type", Value: 1},
				{Key: "ip", Value: 1},
				{Key: "port", Value: 1},
				{Key: "protocol", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_asset_port").
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypePort},
					{Key: "ip", Value: bson.D{{Key: "$exists", Value: true}}},
					{Key: "port", Value: bson.D{{Key: "$exists", Value: true}}},
					{Key: "protocol", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// Query index: org_id + ownership_status + asset_type (for filtering verified/notMine/notSure assets)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "ownership_status", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_org_ownership_type"),
		},
		// Query index: org_id + discovered_at (for sorting by discovery time)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "discovered_at", Value: -1},
			},
			Options: options.Index().SetName("idx_org_discovered"),
		},
		// Query index: org_id + asset_type (for finding all assets of a type for an org)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_org_type"),
		},
		// Index for finding children by parent_id (org-scoped hierarchy)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "parent_id", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_parent_type").
				SetPartialFilterExpression(bson.D{
					{Key: "parent_id", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// Index for filtering by technical status (org-scoped)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "status", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_org_tech_status_type"),
		},
		// Index for time-based queries (org-scoped)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "last_seen", Value: -1},
			},
			Options: options.Index().SetName("idx_org_last_seen"),
		},
		// Index for source-based queries (org-scoped)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "source", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_org_source_type"),
		},
		// Index for scan-based queries: org_id + scan_ids + discovered_at
		// MongoDB automatically creates multikey index for scan_ids array field
		// Supports queries like: {org_id: X, scan_ids: "scan-123"}
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "scan_ids", Value: 1},
				{Key: "discovered_at", Value: -1},
			},
			Options: options.Index().
				SetName("idx_org_scan_time").
				SetPartialFilterExpression(bson.D{
					{Key: "scan_ids", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// Index for counting assets by type per scan: org_id + scan_ids + asset_type
		// MongoDB automatically creates multikey index for scan_ids array field
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "scan_ids", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_scan_type").
				SetPartialFilterExpression(bson.D{
					{Key: "scan_ids", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		logger.Error("Failed to create discoveries indexes", zap.Error(err))
		return err
	}

	logger.Info("Created discoveries collection indexes")
	return nil
}

// ScanCoverageRetention is how long scan_coverage records are kept (TTL on created_at). The
// scan monitor reads the records of the closing scan, and for host_no_longer_found the
// records since a host was last seen, so the retention bounds how far apart the confirming
// scans may be.
const ScanCoverageRetention = 90 * 24 * time.Hour

func ensureScanCoverageIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	indexes := []mongo.IndexModel{
		// UNIQUE: one record per (scan, source, target); ingestion merges duplicates into it.
		{
			Keys: bson.D{
				{Key: "scan_id", Value: 1},
				{Key: "source", Value: 1},
				{Key: "discovery_id", Value: 1},
			},
			Options: options.Index().SetName("idx_scan_source_discovery").SetUnique(true),
		},
		// Absence history of a target, for host_no_longer_found.
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "discovery_id", Value: 1},
				{Key: "source", Value: 1},
				{Key: "created_at", Value: -1},
			},
			Options: options.Index().SetName("idx_org_discovery_source_time"),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetName("ttl_created_at").SetExpireAfterSeconds(int32(ScanCoverageRetention.Seconds())),
		},
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := db.Collection(shared.CollectionScanCoverage).Indexes().CreateMany(ctx, indexes); err != nil {
		logger.Error("Failed to create scan_coverage indexes", zap.Error(err))
		return err
	}
	logger.Info("Created scan_coverage collection indexes")
	return nil
}
