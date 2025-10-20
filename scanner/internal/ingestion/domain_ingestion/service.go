package domain_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Service struct {
	db     *mongo.Database
	redis  *redis.Client
	logger *zap.Logger
}

func NewService(db *mongo.Database, redis *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

// ProcessFinding processes a domain discovery finding and persists it to MongoDB
func (s *Service) ProcessFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
	s.logger.Info("Processing domain discovery finding",
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

	// Handle Shodan discoveries - store in OrgAssets collection
	if finding.Source == "shodan" && finding.Port == nil && finding.IP != nil {
		return s.processOrgAsset(ctx, finding)
	}

	// Skip non-Shodan findings (attack surface ingestion removed from domain ingestion)
	s.logger.Debug("Skipping non-Shodan finding",
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)
	return nil
}

// processOrgAsset processes Shodan domain discoveries and stores them in OrgAssets collection
// Creates/updates both domain asset (asset_type = "domain") and IP asset (asset_type = "ip")
func (s *Service) processOrgAsset(ctx context.Context, finding shared.DiscoveryFinding) error {
	now := time.Now()

	// 1. Upsert domain asset (asset_type = "domain")
	domainAssetID, err := s.upsertDomainAsset(ctx, finding, now)
	if err != nil {
		return err
	}

	// 2. Upsert IP asset (asset_type = "ip", parent_id = domainAssetID)
	ipAssetID, shouldTriggerPortScan, err := s.upsertIPAsset(ctx, finding, domainAssetID, now)
	if err != nil {
		return err
	}

	// 3. Trigger IP discovery job if we have a new IP
	if shouldTriggerPortScan {
		if err := s.publishIPDiscoveryJob(ctx, finding, ipAssetID); err != nil {
			s.logger.Error("Failed to publish IP discovery job",
				zap.String("trace_id", finding.TraceID),
				zap.String("domain", finding.Host),
				zap.String("ip", *finding.IP),
				zap.Error(err),
			)
			// Don't fail the domain ingestion if IP scan trigger fails
		} else {
			s.logger.Info("Triggered IP discovery job",
				zap.String("trace_id", finding.TraceID),
				zap.String("domain", finding.Host),
				zap.String("ip", *finding.IP),
				zap.String("ip_asset_id", ipAssetID),
			)
		}
	}

	return nil
}

// upsertDomainAsset creates or updates a domain asset in org_assets collection
func (s *Service) upsertDomainAsset(ctx context.Context, finding shared.DiscoveryFinding, timestamp time.Time) (string, error) {
	collection := s.db.Collection(shared.CollectionOrgAssets)

	// Check if domain asset already exists
	filter := bson.M{
		"asset_type": shared.AssetTypeDomain,
		"org_id":     finding.OrgID,
		"domain":     finding.Host,
	}

	var existingAsset shared.OrgAsset
	err := collection.FindOne(ctx, filter).Decode(&existingAsset)

	if err == mongo.ErrNoDocuments {
		// Create new domain asset
		domainAssetID := uuid.New().String()
		newAsset := shared.OrgAsset{
			ID:        domainAssetID,
			AssetType: shared.AssetTypeDomain,
			OrgID:     finding.OrgID,
			Source:    finding.Source,
			Status:    finding.Status,
			FirstSeen: timestamp,
			LastSeen:  timestamp,
			Domain:    &finding.Host,
			CurrentIP: finding.IP,
			ResolutionHistory: []shared.ResolutionHistory{
				{
					IP:            *finding.IP,
					ResolvedFrom:  timestamp,
					ResolvedUntil: nil, // Currently active
				},
			},
		}

		doc := bson.M{
			"_id":                newAsset.ID,
			"asset_type":         newAsset.AssetType,
			"org_id":             newAsset.OrgID,
			"source":             newAsset.Source,
			"status":             newAsset.Status,
			"first_seen":         newAsset.FirstSeen,
			"last_seen":          newAsset.LastSeen,
			"domain":             newAsset.Domain,
			"current_ip":         newAsset.CurrentIP,
			"resolution_history": newAsset.ResolutionHistory,
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create domain asset",
				zap.String("domain", finding.Host),
				zap.String("org_id", finding.OrgID),
				zap.Error(err),
			)
			return "", err
		}

		s.logger.Info("Created new domain asset",
			zap.String("asset_id", domainAssetID),
			zap.String("domain", finding.Host),
			zap.String("org_id", finding.OrgID),
			zap.String("ip", *finding.IP),
		)
		return domainAssetID, nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing domain asset",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", err
	}

	// Domain asset exists - update it
	if err := s.updateDomainAssetResolution(ctx, &existingAsset, *finding.IP, timestamp); err != nil {
		return "", err
	}

	return existingAsset.ID, nil
}

// updateDomainAssetResolution updates the resolution history when IP changes
func (s *Service) updateDomainAssetResolution(ctx context.Context, asset *shared.OrgAsset, newIP string, timestamp time.Time) error {
	collection := s.db.Collection(shared.CollectionOrgAssets)

	// Check if the most recent resolution is still active and matches the new IP
	if len(asset.ResolutionHistory) > 0 {
		lastResolution := asset.ResolutionHistory[len(asset.ResolutionHistory)-1]

		// If IP hasn't changed and resolution is still active, only update last_seen
		if lastResolution.IP == newIP && lastResolution.ResolvedUntil == nil {
			update := bson.M{
				"$set": bson.M{
					"last_seen": timestamp,
				},
			}
			_, err := collection.UpdateOne(ctx, bson.M{"_id": asset.ID}, update)
			if err != nil {
				s.logger.Error("Failed to update domain asset last_seen",
					zap.String("domain", *asset.Domain),
					zap.Error(err),
				)
				return err
			}

			s.logger.Debug("IP unchanged, updated last_seen",
				zap.String("domain", *asset.Domain),
				zap.String("ip", newIP),
			)
			return nil
		}

		// If IP has changed, close the current resolution and add new one
		if lastResolution.IP != newIP && lastResolution.ResolvedUntil == nil {
			update := bson.M{
				"$set": bson.M{
					"resolution_history." + fmt.Sprint(len(asset.ResolutionHistory)-1) + ".resolved_until": timestamp,
					"current_ip":  newIP,
					"last_seen":   timestamp,
				},
				"$push": bson.M{
					"resolution_history": shared.ResolutionHistory{
						IP:            newIP,
						ResolvedFrom:  timestamp,
						ResolvedUntil: nil, // Currently active
					},
				},
			}

			_, err := collection.UpdateOne(ctx, bson.M{"_id": asset.ID}, update)
			if err != nil {
				s.logger.Error("Failed to update domain asset resolution",
					zap.String("domain", *asset.Domain),
					zap.Error(err),
				)
				return err
			}

			s.logger.Info("Updated domain asset with new IP resolution",
				zap.String("domain", *asset.Domain),
				zap.String("old_ip", lastResolution.IP),
				zap.String("new_ip", newIP),
			)
			return nil
		}
	}

	// Shouldn't normally reach here, but handle it gracefully
	update := bson.M{
		"$push": bson.M{
			"resolution_history": shared.ResolutionHistory{
				IP:            newIP,
				ResolvedFrom:  timestamp,
				ResolvedUntil: nil,
			},
		},
		"$set": bson.M{
			"current_ip": newIP,
			"last_seen":  timestamp,
		},
	}

	_, err := collection.UpdateOne(ctx, bson.M{"_id": asset.ID}, update)
	if err != nil {
		s.logger.Error("Failed to add resolution to domain asset",
			zap.String("domain", *asset.Domain),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Added new resolution to domain asset",
		zap.String("domain", *asset.Domain),
		zap.String("ip", newIP),
	)
	return nil
}

// upsertIPAsset creates or updates an IP asset in org_assets collection
// Returns (ipAssetID, shouldTriggerPortScan, error)
func (s *Service) upsertIPAsset(ctx context.Context, finding shared.DiscoveryFinding, domainAssetID string, timestamp time.Time) (string, bool, error) {
	collection := s.db.Collection(shared.CollectionOrgAssets)

	// Check if IP asset already exists for this org
	filter := bson.M{
		"asset_type": shared.AssetTypeIP,
		"org_id":     finding.OrgID,
		"ip":         *finding.IP,
	}

	var existingIPAsset shared.OrgAsset
	err := collection.FindOne(ctx, filter).Decode(&existingIPAsset)

	if err == mongo.ErrNoDocuments {
		// Create new IP asset
		ipAssetID := uuid.New().String()
		newIPAsset := shared.OrgAsset{
			ID:            ipAssetID,
			AssetType:     shared.AssetTypeIP,
			OrgID:         finding.OrgID,
			Source:        finding.Source,
			Status:        finding.Status,
			FirstSeen:     timestamp,
			LastSeen:      timestamp,
			IP:            finding.IP,
			ParentID:      &domainAssetID,
			ParentDomains: []string{finding.Host},
		}

		doc := bson.M{
			"_id":            newIPAsset.ID,
			"asset_type":     newIPAsset.AssetType,
			"org_id":         newIPAsset.OrgID,
			"source":         newIPAsset.Source,
			"status":         newIPAsset.Status,
			"first_seen":     newIPAsset.FirstSeen,
			"last_seen":      newIPAsset.LastSeen,
			"ip":             newIPAsset.IP,
			"parent_id":      newIPAsset.ParentID,
			"parent_domains": newIPAsset.ParentDomains,
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create IP asset",
				zap.String("ip", *finding.IP),
				zap.String("org_id", finding.OrgID),
				zap.Error(err),
			)
			return "", false, err
		}

		s.logger.Info("Created new IP asset",
			zap.String("asset_id", ipAssetID),
			zap.String("ip", *finding.IP),
			zap.String("org_id", finding.OrgID),
			zap.String("parent_domain", finding.Host),
		)
		return ipAssetID, true, nil // Trigger port scan for new IP
	}

	if err != nil {
		s.logger.Error("Failed to check existing IP asset",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", false, err
	}

	// IP asset exists - update last_seen and add parent domain if not already present
	updateDoc := bson.M{
		"$set": bson.M{
			"last_seen": timestamp,
		},
	}

	// Add parent domain to the list if not already present
	alreadyHasParent := false
	for _, domain := range existingIPAsset.ParentDomains {
		if domain == finding.Host {
			alreadyHasParent = true
			break
		}
	}

	if !alreadyHasParent {
		updateDoc["$addToSet"] = bson.M{
			"parent_domains": finding.Host,
		}
		s.logger.Info("Adding parent domain to existing IP asset",
			zap.String("ip", *finding.IP),
			zap.String("new_parent_domain", finding.Host),
		)
	}

	_, err = collection.UpdateOne(ctx, bson.M{"_id": existingIPAsset.ID}, updateDoc)
	if err != nil {
		s.logger.Error("Failed to update IP asset",
			zap.String("ip", *finding.IP),
			zap.Error(err),
		)
		return "", false, err
	}

	s.logger.Debug("Updated existing IP asset",
		zap.String("asset_id", existingIPAsset.ID),
		zap.String("ip", *finding.IP),
	)
	return existingIPAsset.ID, false, nil // Don't trigger port scan for existing IP
}

// publishIPDiscoveryJob publishes an IP discovery job to trigger port scanning
func (s *Service) publishIPDiscoveryJob(ctx context.Context, finding shared.DiscoveryFinding, ipAssetID string) error {
	// Create IP discovery job
	ipJob := shared.IPDiscoveryJob{
		TraceID: finding.TraceID,
		OrgID:   finding.OrgID,
		IP:      *finding.IP,
		Metadata: map[string]interface{}{
			"source":       "domain_discovery",
			"domain":       finding.Host,
			"ip_asset_id":  ipAssetID,
		},
		Created: time.Now(),
	}

	// Use shared publisher utility
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamIPDiscoveryQueue, ipJob); err != nil {
		return fmt.Errorf("failed to publish IP discovery job: %w", err)
	}

	return nil
}
