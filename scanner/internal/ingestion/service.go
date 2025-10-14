package ingestion

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type Service struct {
	db     *mongo.Database
	logger *zap.Logger
}

func NewService(db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// ProcessFinding processes a discovery finding and persists it to MongoDB
func (s *Service) ProcessFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
	s.logger.Info("Processing discovery finding",
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)

	// Check if asset already exists
	existingAsset, err := s.findExistingAsset(ctx, finding.Host, finding.Port, finding.Protocol)
	if err != nil && err != mongo.ErrNoDocuments {
		s.logger.Error("Failed to check existing asset",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return err
	}

	now := time.Now()

	if existingAsset != nil {
		// Asset exists - update last_seen and merge metadata
		return s.updateAssetLastSeen(ctx, existingAsset.ID, now, finding.Source, finding.Metadata)
	}

	// Create new asset
	asset := &shared.AttackSurfaceAsset{
		ID:        uuid.New().String(),
		ParentID:  finding.ParentID,
		Host:      finding.Host,
		Port:      finding.Port,
		Protocol:  finding.Protocol,
		Status:    finding.Status,
		FirstSeen: now,
		LastSeen:  now,
		Metadata:  s.buildMetadata(finding.Source, finding.Metadata),
	}

	return s.createAsset(ctx, asset)
}

// buildMetadata builds metadata with source information
func (s *Service) buildMetadata(source string, metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["source"] = source
	return metadata
}

// findExistingAsset checks if an asset already exists
func (s *Service) findExistingAsset(ctx context.Context, host string, port *int, protocol *string) (*shared.AttackSurfaceAsset, error) {
	collection := s.db.Collection(shared.CollectionAttackSurface)

	filter := bson.M{
		"host": host,
	}

	// Handle port comparison (can be nil or specific value)
	if port != nil {
		filter["port"] = *port
	} else {
		filter["port"] = bson.M{"$exists": false}
	}

	// Handle protocol comparison (can be nil or specific value)
	if protocol != nil {
		filter["protocol"] = *protocol
	} else {
		filter["protocol"] = bson.M{"$exists": false}
	}

	var asset shared.AttackSurfaceAsset
	err := collection.FindOne(ctx, filter).Decode(&asset)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err
	}

	return &asset, nil
}

// updateAssetLastSeen updates the last_seen timestamp and merges metadata
func (s *Service) updateAssetLastSeen(ctx context.Context, assetID string, lastSeen time.Time, source string, metadata map[string]interface{}) error {
	collection := s.db.Collection(shared.CollectionAttackSurface)

	update := bson.M{
		"$set": bson.M{
			"last_seen":     lastSeen,
			"metadata.source": source, // Always update source
		},
	}

	// Merge additional metadata if provided
	if metadata != nil && len(metadata) > 0 {
		for key, value := range metadata {
			if key != "source" { // Skip source as it's already set
				update["$set"].(bson.M)["metadata."+key] = value
			}
		}
	}

	filter := bson.M{"_id": assetID}
	_, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		s.logger.Error("Failed to update asset last_seen",
			zap.String("asset_id", assetID),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Updated asset last_seen",
		zap.String("asset_id", assetID),
		zap.Time("last_seen", lastSeen),
		zap.String("source", source),
	)

	return nil
}

// createAsset creates a new attack surface asset
func (s *Service) createAsset(ctx context.Context, asset *shared.AttackSurfaceAsset) error {
	collection := s.db.Collection(shared.CollectionAttackSurface)

	// Use _id field explicitly for MongoDB
	doc := bson.M{
		"_id":        asset.ID,
		"host":       asset.Host,
		"status":     asset.Status,
		"first_seen": asset.FirstSeen,
		"last_seen":  asset.LastSeen,
	}

	// Add optional fields
	if asset.ParentID != nil {
		doc["parent_id"] = *asset.ParentID
	}
	if asset.Port != nil {
		doc["port"] = *asset.Port
	}
	if asset.Protocol != nil {
		doc["protocol"] = *asset.Protocol
	}
	if asset.Metadata != nil && len(asset.Metadata) > 0 {
		doc["metadata"] = asset.Metadata
	}

	_, err := collection.InsertOne(ctx, doc, options.InsertOne())
	if err != nil {
		s.logger.Error("Failed to create asset",
			zap.String("asset_id", asset.ID),
			zap.String("host", asset.Host),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Created new attack surface asset",
		zap.String("asset_id", asset.ID),
		zap.String("host", asset.Host),
		zap.String("source", asset.Metadata["source"].(string)),
	)

	return nil
}
