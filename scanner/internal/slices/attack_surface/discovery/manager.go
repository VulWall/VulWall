package discovery

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// Manager orchestrates multiple discovery providers and handles asset creation
type Manager struct {
	providers         []AttackSurfaceProvider
	db                *mongo.Database
	logger            *zap.Logger
	collectionName    string
	assetStatusActive string
	findAssetFunc     FindAssetFunc
	updateAssetFunc   UpdateAssetFunc
}

// FindAssetFunc is a function type for finding existing assets
type FindAssetFunc func(ctx context.Context, orgID, host string, port *int, protocol *string) (AssetInfo, error)

// UpdateAssetFunc is a function type for updating asset last_seen
type UpdateAssetFunc func(ctx context.Context, assetID string, lastSeen time.Time, metadata map[string]interface{}) error

// AssetInfo contains minimal asset information for checking existence
type AssetInfo struct {
	ID     string
	Exists bool
}

// NewManager creates a new discovery manager
func NewManager(
	providers []AttackSurfaceProvider,
	db *mongo.Database,
	collectionName string,
	assetStatusActive string,
	logger *zap.Logger,
	findAssetFunc FindAssetFunc,
	updateAssetFunc UpdateAssetFunc,
) *Manager {
	return &Manager{
		providers:         providers,
		db:                db,
		logger:            logger,
		collectionName:    collectionName,
		assetStatusActive: assetStatusActive,
		findAssetFunc:     findAssetFunc,
		updateAssetFunc:   updateAssetFunc,
	}
}

// DiscoverAndCreateAssets runs all discovery providers and creates assets in the database
func (m *Manager) DiscoverAndCreateAssets(
	ctx context.Context,
	parentID, orgID string,
	target DiscoveryTarget,
) error {
	m.logger.Info("Starting discovery",
		zap.String("org_id", orgID),
		zap.String("parent_id", parentID),
		zap.String("host", target.Host),
		zap.String("type", target.Type),
		zap.Int("providers", len(m.providers)),
	)

	var allAssets []DiscoveredAsset

	// Run all enabled providers
	for _, provider := range m.providers {
		m.logger.Info("Running discovery provider",
			zap.String("provider", provider.Name()),
			zap.String("target", target.Host),
		)

		discovered, err := provider.Discover(ctx, target)
		if err != nil {
			m.logger.Error("Provider failed",
				zap.String("provider", provider.Name()),
				zap.String("target", target.Host),
				zap.Error(err),
			)
			continue
		}

		m.logger.Info("Provider completed",
			zap.String("provider", provider.Name()),
			zap.Int("assets_found", len(discovered)),
		)

		allAssets = append(allAssets, discovered...)
	}

	if len(allAssets) == 0 {
		m.logger.Info("No assets discovered", zap.String("target", target.Host))
		return nil
	}

	// Create or update assets in database
	return m.createDiscoveredAssets(ctx, parentID, orgID, allAssets)
}

// createDiscoveredAssets creates or updates discovered assets in the database
func (m *Manager) createDiscoveredAssets(
	ctx context.Context,
	parentID, orgID string,
	assets []DiscoveredAsset,
) error {
	now := time.Now()
	collection := m.db.Collection(m.collectionName)

	for _, asset := range assets {
		// Check if asset already exists
		existing, err := m.findAssetFunc(ctx, orgID, asset.Host, asset.Port, asset.Protocol)
		if err != nil {
			m.logger.Error("Failed to check existing asset",
				zap.String("host", asset.Host),
				zap.Error(err),
			)
			continue
		}

		if existing.Exists {
			// Update last_seen for existing asset
			if err := m.updateAssetFunc(ctx, existing.ID, now, asset.Metadata); err != nil {
				m.logger.Error("Failed to update asset last_seen",
					zap.String("host", asset.Host),
					zap.Error(err),
				)
			}
			continue
		}

		// Create new asset
		assetID := uuid.New().String()
		doc := bson.M{
			"_id":        assetID,
			"org_id":     orgID,
			"parent_id":  parentID,
			"host":       asset.Host,
			"status":     m.assetStatusActive,
			"first_seen": now,
			"last_seen":  now,
		}

		// Add optional fields
		if asset.Port != nil {
			doc["port"] = *asset.Port
		}
		if asset.Protocol != nil {
			doc["protocol"] = *asset.Protocol
		}
		if asset.Metadata != nil && len(asset.Metadata) > 0 {
			doc["metadata"] = asset.Metadata
		}

		_, err = collection.InsertOne(ctx, doc, options.InsertOne())
		if err != nil {
			m.logger.Error("Failed to create asset",
				zap.String("asset_id", assetID),
				zap.String("host", asset.Host),
				zap.Error(err),
			)
			continue
		}

		m.logger.Info("Created discovered asset",
			zap.String("asset_id", assetID),
			zap.String("org_id", orgID),
			zap.String("host", asset.Host),
		)
	}

	return nil
}
