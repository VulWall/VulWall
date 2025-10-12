package attack_surface

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

// ProcessJob processes an attack surface discovery job
func (s *Service) ProcessJob(ctx context.Context, job shared.AttackSurfaceJob) error {
	s.logger.Info("Processing attack surface job",
		zap.String("job_id", job.JobID),
		zap.String("root_id", job.RootID),
		zap.String("host", job.Host),
	)

	// Check if asset already exists
	existingAsset, err := s.findExistingAsset(ctx, job.RootID, job.Host, job.Port)
	if err != nil && err != mongo.ErrNoDocuments {
		s.logger.Error("Failed to check existing asset",
			zap.String("job_id", job.JobID),
			zap.Error(err),
		)
		return err
	}

	now := time.Now()

	if existingAsset != nil {
		// Asset exists - update last_seen
		return s.updateAssetLastSeen(ctx, existingAsset.ID, now, job.Metadata)
	}

	// Create new asset
	asset := &shared.AttackSurfaceAsset{
		ID:        uuid.New().String(),
		RootID:    job.RootID,
		ParentID:  job.ParentID,
		Host:      job.Host,
		Port:      job.Port,
		Status:    shared.AssetStatusActive,
		FirstSeen: now,
		LastSeen:  now,
		Metadata:  job.Metadata,
	}

	return s.createAsset(ctx, asset)
}

// findExistingAsset checks if an asset already exists
func (s *Service) findExistingAsset(ctx context.Context, rootID, host string, port *int) (*shared.AttackSurfaceAsset, error) {
	collection := s.db.Collection(shared.CollectionAttackSurface)

	filter := bson.M{
		"root_id": rootID,
		"host":    host,
	}

	// Handle port comparison (can be nil or specific value)
	if port != nil {
		filter["port"] = *port
	} else {
		filter["port"] = bson.M{"$exists": false}
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

// updateAssetLastSeen updates the last_seen timestamp and optionally merges metadata
func (s *Service) updateAssetLastSeen(ctx context.Context, assetID string, lastSeen time.Time, metadata map[string]interface{}) error {
	collection := s.db.Collection(shared.CollectionAttackSurface)

	update := bson.M{
		"$set": bson.M{
			"last_seen": lastSeen,
			"status":    shared.AssetStatusActive,
		},
	}

	// Merge metadata if provided
	if metadata != nil && len(metadata) > 0 {
		for key, value := range metadata {
			update["$set"].(bson.M)["metadata."+key] = value
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
	)

	return nil
}

// createAsset creates a new attack surface asset
func (s *Service) createAsset(ctx context.Context, asset *shared.AttackSurfaceAsset) error {
	collection := s.db.Collection(shared.CollectionAttackSurface)

	// Use _id field explicitly for MongoDB
	doc := bson.M{
		"_id":        asset.ID,
		"root_id":    asset.RootID,
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
		zap.String("root_id", asset.RootID),
		zap.String("host", asset.Host),
	)

	return nil
}
