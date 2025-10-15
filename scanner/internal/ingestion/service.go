package ingestion

import (
	"context"
	"fmt"
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
		zap.String("org_id", finding.OrgID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)

	// Validate source is present (required) - skip if missing
	if finding.Source == "" {
		s.logger.Warn("Skipping finding: missing source",
			zap.String("trace_id", finding.TraceID),
			zap.String("org_id", finding.OrgID),
			zap.String("host", finding.Host),
		)
		return nil
	}

	// Handle Shodan discoveries - store in OrgDomains collection
	if finding.Source == "shodan" && finding.Port == nil && finding.IP != nil {
		return s.processOrgDomain(ctx, finding)
	}

	// Handle other discoveries - store in AttackSurface collection
	return s.processAttackSurface(ctx, finding)
}

// processOrgDomain processes Shodan domain discoveries and stores them in OrgDomains collection
func (s *Service) processOrgDomain(ctx context.Context, finding shared.DiscoveryFinding) error {
	collection := s.db.Collection(shared.CollectionOrgDomains)
	now := time.Now()

	// Check if domain already exists for this org
	filter := bson.M{
		"org_id": finding.OrgID,
		"domain": finding.Host,
	}

	var existingDomain shared.OrgDomain
	err := collection.FindOne(ctx, filter).Decode(&existingDomain)

	if err == mongo.ErrNoDocuments {
		// Create new OrgDomain with first IP resolution
		newDomain := &shared.OrgDomain{
			ID:     uuid.New().String(),
			OrgID:  finding.OrgID,
			Domain: finding.Host,
			Source: finding.Source,
			ResolutionHistory: []shared.ResolutionHistory{
				{
					IP:            *finding.IP,
					ResolvedFrom:  now,
					ResolvedUntil: nil, // Currently active
				},
			},
		}

		doc := bson.M{
			"_id":                newDomain.ID,
			"org_id":             newDomain.OrgID,
			"domain":             newDomain.Domain,
			"source":             newDomain.Source,
			"resolution_history": newDomain.ResolutionHistory,
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create OrgDomain",
				zap.String("domain", finding.Host),
				zap.String("org_id", finding.OrgID),
				zap.Error(err),
			)
			return err
		}

		s.logger.Info("Created new OrgDomain",
			zap.String("domain", finding.Host),
			zap.String("org_id", finding.OrgID),
			zap.String("ip", *finding.IP),
		)
		return nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing OrgDomain",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return err
	}

	// Domain exists - check if IP has changed
	return s.updateOrgDomainResolution(ctx, &existingDomain, *finding.IP, now)
}

// updateOrgDomainResolution updates the resolution history when IP changes
func (s *Service) updateOrgDomainResolution(ctx context.Context, domain *shared.OrgDomain, newIP string, timestamp time.Time) error {
	collection := s.db.Collection(shared.CollectionOrgDomains)

	// Check if the most recent resolution is still active and matches the new IP
	if len(domain.ResolutionHistory) > 0 {
		lastResolution := domain.ResolutionHistory[len(domain.ResolutionHistory)-1]

		// If IP hasn't changed and resolution is still active, no update needed
		if lastResolution.IP == newIP && lastResolution.ResolvedUntil == nil {
			s.logger.Debug("IP unchanged, no update needed",
				zap.String("domain", domain.Domain),
				zap.String("ip", newIP),
			)
			return nil
		}

		// If IP has changed, close the current resolution and add new one
		if lastResolution.IP != newIP && lastResolution.ResolvedUntil == nil {
			// Close the previous resolution
			update := bson.M{
				"$set": bson.M{
					"resolution_history." + fmt.Sprint(len(domain.ResolutionHistory)-1) + ".resolved_until": timestamp,
				},
				"$push": bson.M{
					"resolution_history": shared.ResolutionHistory{
						IP:            newIP,
						ResolvedFrom:  timestamp,
						ResolvedUntil: nil, // Currently active
					},
				},
			}

			_, err := collection.UpdateOne(ctx, bson.M{"_id": domain.ID}, update)
			if err != nil {
				s.logger.Error("Failed to update OrgDomain resolution",
					zap.String("domain", domain.Domain),
					zap.Error(err),
				)
				return err
			}

			s.logger.Info("Updated OrgDomain with new IP resolution",
				zap.String("domain", domain.Domain),
				zap.String("old_ip", lastResolution.IP),
				zap.String("new_ip", newIP),
			)
			return nil
		}
	}

	// If we get here, add a new resolution (shouldn't normally happen, but handle it)
	update := bson.M{
		"$push": bson.M{
			"resolution_history": shared.ResolutionHistory{
				IP:            newIP,
				ResolvedFrom:  timestamp,
				ResolvedUntil: nil,
			},
		},
	}

	_, err := collection.UpdateOne(ctx, bson.M{"_id": domain.ID}, update)
	if err != nil {
		s.logger.Error("Failed to add resolution to OrgDomain",
			zap.String("domain", domain.Domain),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Added new resolution to OrgDomain",
		zap.String("domain", domain.Domain),
		zap.String("ip", newIP),
	)
	return nil
}

// processAttackSurface processes non-domain findings and stores them in AttackSurface collection
func (s *Service) processAttackSurface(ctx context.Context, finding shared.DiscoveryFinding) error {
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
