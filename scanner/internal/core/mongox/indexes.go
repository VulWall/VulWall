package mongox

import (
	"context"
	"time"

	"github.com/vulwall/scanners/internal/shared"
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
		// Query index: org_id + org_asset_status + asset_type (for filtering confirmed/pending/dismissed assets)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "org_asset_status", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_org_status_type"),
		},
		// Query index: org_id + assigned_at (for sorting by assignment time)
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "assigned_at", Value: -1},
			},
			Options: options.Index().SetName("idx_org_assigned"),
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
