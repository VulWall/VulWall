package attack_surface

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/slices/attack_surface/discovery"
	"github.com/vulwall/scanners/internal/slices/attack_surface/discovery/shodan"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type Service struct {
	db               *mongo.Database
	logger           *zap.Logger
	discoveryManager *discovery.Manager
}

func NewService(db *mongo.Database, shodanAPIKey string, logger *zap.Logger) *Service {
	s := &Service{
		db:     db,
		logger: logger,
	}

	// Initialize discovery providers
	providers := []discovery.AttackSurfaceProvider{
		shodan.NewProvider(shodanAPIKey, logger),
	}

	// Create discovery manager with callbacks to service methods
	s.discoveryManager = discovery.NewManager(
		providers,
		db,
		CollectionAttackSurface,
		AssetStatusActive,
		logger,
		s.findAssetForManager,
		s.updateAssetLastSeen,
	)

	return s
}

// ProcessJob processes an attack surface discovery job
func (s *Service) ProcessJob(ctx context.Context, job AttackSurfaceJob) error {
	s.logger.Info("Processing attack surface job",
		zap.String("trace_id", job.TraceID),
		zap.String("host", job.Host),
	)

	// Check if asset already exists
	existingAsset, err := s.findExistingAsset(ctx, job.Host, job.Port, job.Protocol)
	if err != nil && err != mongo.ErrNoDocuments {
		s.logger.Error("Failed to check existing asset",
			zap.String("trace_id", job.TraceID),
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
	asset := &AttackSurfaceAsset{
		ID:        uuid.New().String(),
		ParentID:  job.ParentID,
		Host:      job.Host,
		Port:      job.Port,
		Protocol:  job.Protocol,
		Status:    AssetStatusActive,
		FirstSeen: now,
		LastSeen:  now,
		Metadata:  job.Metadata,
	}

	if err := s.createAsset(ctx, asset); err != nil {
		return err
	}

	// Trigger discovery for root assets (no parent)
	if job.ParentID == nil {
		targetType := s.determineTargetType(job.Host)
		target := discovery.DiscoveryTarget{
			Host:     job.Host,
			Port:     job.Port,
			Protocol: job.Protocol,
			Type:     targetType,
		}

		go func() {
			if err := s.discoveryManager.DiscoverAndCreateAssets(
				context.Background(),
				asset.ID,
				target,
			); err != nil {
				s.logger.Error("Discovery failed",
					zap.String("asset_id", asset.ID),
					zap.String("host", job.Host),
					zap.Error(err),
				)
			}
		}()
	}

	return nil
}

// findExistingAsset checks if an asset already exists
func (s *Service) findExistingAsset(ctx context.Context, host string, port *int, protocol *string) (*AttackSurfaceAsset, error) {
	collection := s.db.Collection(CollectionAttackSurface)

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
	// Protocol matters: 192.168.1.1:53/tcp vs 192.168.1.1:53/udp are different assets
	if protocol != nil {
		filter["protocol"] = *protocol
	} else {
		filter["protocol"] = bson.M{"$exists": false}
	}

	var asset AttackSurfaceAsset
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
	collection := s.db.Collection(CollectionAttackSurface)

	update := bson.M{
		"$set": bson.M{
			"last_seen": lastSeen,
			"status":    AssetStatusActive,
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
func (s *Service) createAsset(ctx context.Context, asset *AttackSurfaceAsset) error {
	collection := s.db.Collection(CollectionAttackSurface)

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
	)

	return nil
}

// findAssetForManager is a helper function for the discovery manager to check if an asset exists
func (s *Service) findAssetForManager(ctx context.Context, host string, port *int, protocol *string) (discovery.AssetInfo, error) {
	asset, err := s.findExistingAsset(ctx, host, port, protocol)
	if err != nil {
		return discovery.AssetInfo{Exists: false}, err
	}

	if asset != nil {
		return discovery.AssetInfo{
			ID:     asset.ID,
			Exists: true,
		}, nil
	}

	return discovery.AssetInfo{Exists: false}, nil
}

// determineTargetType determines the type of target (domain, ip, cidr)
func (s *Service) determineTargetType(host string) string {
	// Simple heuristic: if it contains only numbers and dots, it's an IP
	// For production, use proper IP parsing
	isIP := true
	for _, c := range host {
		if !(c >= '0' && c <= '9' || c == '.') {
			isIP = false
			break
		}
	}

	if isIP {
		return TargetTypeIP
	}
	return TargetTypeDomain
}
