package port_ingestion

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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

// ProcessFinding processes a port discovery finding and persists it to MongoDB attack_surface collection
func (s *Service) ProcessFinding(ctx context.Context, finding shared.IPDiscoveryFinding) error {
	s.logger.Info("Processing port discovery finding",
		zap.String("trace_id", finding.TraceID),
		zap.String("org_id", finding.OrgID),
		zap.String("source", finding.Source),
		zap.String("ip", finding.IP),
		zap.Int("port", finding.Port),
	)

	// Validate source is present (required) - skip if missing
	if finding.Source == "" {
		s.logger.Warn("Skipping finding: missing source",
			zap.String("trace_id", finding.TraceID),
			zap.String("org_id", finding.OrgID),
			zap.String("ip", finding.IP),
		)
		return nil
	}

	// Store port finding in attack_surface collection
	return s.processAttackSurface(ctx, finding)
}

// processAttackSurface stores port findings in the attack_surface collection
// and links them to organizations via org_attack_surface collection
func (s *Service) processAttackSurface(ctx context.Context, finding shared.IPDiscoveryFinding) error {
	attackSurfaceCol := s.db.Collection(shared.CollectionAttackSurface)
	orgAttackSurfaceCol := s.db.Collection(shared.CollectionOrgAttackSurface)
	now := time.Now()

	// Check if this asset (IP + port + protocol) already exists
	filter := bson.M{
		"host":     finding.IP,
		"port":     finding.Port,
		"protocol": finding.Protocol,
	}

	var existingAsset shared.AttackSurfaceAsset
	err := attackSurfaceCol.FindOne(ctx, filter).Decode(&existingAsset)

	var assetID string

	if err == mongo.ErrNoDocuments {
		// Create new attack surface asset
		protocol := finding.Protocol
		newAsset := shared.AttackSurfaceAsset{
			ID:        uuid.New().String(),
			Host:      finding.IP,
			Port:      &finding.Port,
			Protocol:  &protocol,
			Status:    finding.Status,
			Source:    finding.Source,
			Banner:    finding.Banner,
			FirstSeen: now,
			LastSeen:  now,
			Metadata:  finding.Metadata,
		}

		doc := bson.M{
			"_id":       newAsset.ID,
			"host":      newAsset.Host,
			"port":      newAsset.Port,
			"protocol":  newAsset.Protocol,
			"status":    newAsset.Status,
			"source":    newAsset.Source,
			"first_seen": newAsset.FirstSeen,
			"last_seen": newAsset.LastSeen,
		}

		// Only include banner if not nil
		if newAsset.Banner != nil {
			doc["banner"] = newAsset.Banner
		}

		// Only include metadata if not empty
		if len(newAsset.Metadata) > 0 {
			doc["metadata"] = newAsset.Metadata
		}

		_, err := attackSurfaceCol.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create AttackSurfaceAsset",
				zap.String("ip", finding.IP),
				zap.Int("port", finding.Port),
				zap.Error(err),
			)
			return err
		}

		assetID = newAsset.ID

		s.logger.Info("Created new AttackSurfaceAsset",
			zap.String("asset_id", assetID),
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
			zap.String("protocol", finding.Protocol),
		)
	} else if err != nil {
		s.logger.Error("Failed to check existing AttackSurfaceAsset",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return err
	} else {
		// Asset exists - update last_seen, status, source, and banner
		assetID = existingAsset.ID

		update := bson.M{
			"$set": bson.M{
				"last_seen": now,
				"status":    finding.Status,
				"source":    finding.Source, // Update source (in case different tool rediscovered)
			},
		}

		// Update banner if new scan provides it
		if finding.Banner != nil {
			update["$set"].(bson.M)["banner"] = finding.Banner
		}

		// Update metadata if new info is available
		if len(finding.Metadata) > 0 {
			// Merge metadata
			if existingAsset.Metadata == nil {
				existingAsset.Metadata = make(map[string]interface{})
			}
			for k, v := range finding.Metadata {
				existingAsset.Metadata[k] = v
			}
			update["$set"].(bson.M)["metadata"] = existingAsset.Metadata
		}

		_, err = attackSurfaceCol.UpdateOne(ctx, bson.M{"_id": existingAsset.ID}, update)
		if err != nil {
			s.logger.Error("Failed to update AttackSurfaceAsset",
				zap.String("ip", finding.IP),
				zap.Int("port", finding.Port),
				zap.Error(err),
			)
			return err
		}

		s.logger.Info("Updated AttackSurfaceAsset",
			zap.String("asset_id", assetID),
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
			zap.String("protocol", finding.Protocol),
		)
	}

	// Now link the asset to the organization in org_attack_surface collection
	return s.linkAssetToOrg(ctx, orgAttackSurfaceCol, assetID, finding.OrgID, finding.Source, now)
}

// linkAssetToOrg creates or updates the relationship between an asset and an organization
func (s *Service) linkAssetToOrg(ctx context.Context, col *mongo.Collection, assetID, orgID, source string, timestamp time.Time) error {
	// Check if this relationship already exists
	filter := bson.M{
		"attacksurface_id": assetID,
		"org_id":           orgID,
	}

	var existingLink shared.OrgAttackSurface
	err := col.FindOne(ctx, filter).Decode(&existingLink)

	if err == mongo.ErrNoDocuments {
		// Create new org-asset link with "confirmed" status
		newLink := shared.OrgAttackSurface{
			ID:              uuid.New().String(),
			AttackSurfaceID: assetID,
			OrgID:           orgID,
			Status:          shared.OrgAssetStatusConfirmed,
			AssignedAt:      timestamp,
		}

		doc := bson.M{
			"_id":              newLink.ID,
			"attacksurface_id": newLink.AttackSurfaceID,
			"org_id":           newLink.OrgID,
			"status":           newLink.Status,
			"assigned_at":      newLink.AssignedAt,
		}

		_, err := col.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create OrgAttackSurface link",
				zap.String("asset_id", assetID),
				zap.String("org_id", orgID),
				zap.Error(err),
			)
			return err
		}

		s.logger.Info("Created OrgAttackSurface link",
			zap.String("asset_id", assetID),
			zap.String("org_id", orgID),
			zap.String("source", source),
		)
		return nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing OrgAttackSurface link",
			zap.String("asset_id", assetID),
			zap.String("org_id", orgID),
			zap.Error(err),
		)
		return err
	}

	// Link already exists - optionally update it (e.g., refresh source)
	s.logger.Debug("OrgAttackSurface link already exists",
		zap.String("asset_id", assetID),
		zap.String("org_id", orgID),
		zap.String("status", existingLink.Status),
	)

	return nil
}
