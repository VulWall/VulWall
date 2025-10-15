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
func (s *Service) processAttackSurface(ctx context.Context, finding shared.IPDiscoveryFinding) error {
	collection := s.db.Collection(shared.CollectionAttackSurface)
	now := time.Now()

	// Check if this asset (IP + port + protocol) already exists
	filter := bson.M{
		"host":     finding.IP,
		"port":     finding.Port,
		"protocol": finding.Protocol,
	}

	var existingAsset shared.AttackSurfaceAsset
	err := collection.FindOne(ctx, filter).Decode(&existingAsset)

	if err == mongo.ErrNoDocuments {
		// Create new attack surface asset
		protocol := finding.Protocol
		newAsset := shared.AttackSurfaceAsset{
			ID:        uuid.New().String(),
			ParentID:  finding.ParentID,
			Host:      finding.IP,
			Port:      &finding.Port,
			Protocol:  &protocol,
			Status:    finding.Status,
			FirstSeen: now,
			LastSeen:  now,
			Metadata:  finding.Metadata,
		}

		// Add org_id and source to metadata
		if newAsset.Metadata == nil {
			newAsset.Metadata = make(map[string]interface{})
		}
		newAsset.Metadata["org_id"] = finding.OrgID
		newAsset.Metadata["source"] = finding.Source

		doc := bson.M{
			"_id":        newAsset.ID,
			"parent_id":  newAsset.ParentID,
			"host":       newAsset.Host,
			"port":       newAsset.Port,
			"protocol":   newAsset.Protocol,
			"status":     newAsset.Status,
			"first_seen": newAsset.FirstSeen,
			"last_seen":  newAsset.LastSeen,
			"metadata":   newAsset.Metadata,
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create AttackSurfaceAsset",
				zap.String("ip", finding.IP),
				zap.Int("port", finding.Port),
				zap.String("org_id", finding.OrgID),
				zap.Error(err),
			)
			return err
		}

		s.logger.Info("Created new AttackSurfaceAsset",
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
			zap.String("protocol", finding.Protocol),
			zap.String("org_id", finding.OrgID),
		)
		return nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing AttackSurfaceAsset",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return err
	}

	// Asset exists - update last_seen and status
	update := bson.M{
		"$set": bson.M{
			"last_seen": now,
			"status":    finding.Status,
		},
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

	_, err = collection.UpdateOne(ctx, bson.M{"_id": existingAsset.ID}, update)
	if err != nil {
		s.logger.Error("Failed to update AttackSurfaceAsset",
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Updated AttackSurfaceAsset",
		zap.String("ip", finding.IP),
		zap.Int("port", finding.Port),
		zap.String("protocol", finding.Protocol),
		zap.String("org_id", finding.OrgID),
	)
	return nil
}
