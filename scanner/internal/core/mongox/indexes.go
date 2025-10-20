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

	// Org assets collection indexes
	if err := ensureOrgAssetsIndexes(ctx, db, logger); err != nil {
		return err
	}

	logger.Info("All MongoDB indexes created successfully")
	return nil
}

func ensureDiscoveriesIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	collection := db.Collection(shared.CollectionDiscoveries)

	indexes := []mongo.IndexModel{
		// Index for finding domains by name
		{
			Keys: bson.D{
				{Key: "asset_type", Value: 1},
				{Key: "domain", Value: 1},
			},
			Options: options.Index().
				SetName("idx_asset_type_domain").
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypeDomain},
				}),
		},
		// Index for finding subdomains by name
		{
			Keys: bson.D{
				{Key: "asset_type", Value: 1},
				{Key: "subdomain", Value: 1},
			},
			Options: options.Index().
				SetName("idx_asset_type_subdomain").
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypeSubdomain},
				}),
		},
		// Index for finding IPs
		{
			Keys: bson.D{
				{Key: "asset_type", Value: 1},
				{Key: "ip", Value: 1},
			},
			Options: options.Index().
				SetName("idx_asset_type_ip").
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypeIP},
				}),
		},
		// Index for finding ports by IP + port + protocol (compound unique)
		{
			Keys: bson.D{
				{Key: "asset_type", Value: 1},
				{Key: "ip", Value: 1},
				{Key: "port", Value: 1},
				{Key: "protocol", Value: 1},
			},
			Options: options.Index().
				SetName("idx_asset_type_ip_port_protocol").
				SetPartialFilterExpression(bson.D{
					{Key: "asset_type", Value: shared.AssetTypePort},
				}),
		},
		// Index for finding children by parent_id
		{
			Keys: bson.D{
				{Key: "parent_id", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().
				SetName("idx_parent_id_asset_type").
				SetPartialFilterExpression(bson.D{
					{Key: "parent_id", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
		// Index for filtering by status
		{
			Keys: bson.D{
				{Key: "status", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_status_asset_type"),
		},
		// Index for time-based queries
		{
			Keys: bson.D{
				{Key: "last_seen", Value: -1},
			},
			Options: options.Index().SetName("idx_last_seen"),
		},
		// Index for source-based queries
		{
			Keys: bson.D{
				{Key: "source", Value: 1},
				{Key: "asset_type", Value: 1},
			},
			Options: options.Index().SetName("idx_source_asset_type"),
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

func ensureOrgAssetsIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	collection := db.Collection(shared.CollectionOrgAssets)

	indexes := []mongo.IndexModel{
		// Unique index: one org can only have one link to each asset
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "asset_id", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_id_asset_id").
				SetUnique(true),
		},
		// Index for finding all assets for an org
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "status", Value: 1},
			},
			Options: options.Index().SetName("idx_org_id_status"),
		},
		// Index for finding all orgs that have a specific asset
		{
			Keys: bson.D{
				{Key: "asset_id", Value: 1},
			},
			Options: options.Index().SetName("idx_asset_id"),
		},
		// Index for time-based queries
		{
			Keys: bson.D{
				{Key: "assigned_at", Value: -1},
			},
			Options: options.Index().SetName("idx_assigned_at"),
		},
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		logger.Error("Failed to create org_assets indexes", zap.Error(err))
		return err
	}

	logger.Info("Created org_assets collection indexes")
	return nil
}
