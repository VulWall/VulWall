package domain_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
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

	// Validate source is present (required)
	if finding.Source == "" {
		s.logger.Warn("Skipping finding: missing source",
			zap.String("trace_id", finding.TraceID),
			zap.String("org_id", finding.OrgID),
			zap.String("host", finding.Host),
		)
		return nil
	}

	// Validate IP is present for domain discoveries
	if finding.IP == nil || *finding.IP == "" {
		s.logger.Warn("Skipping finding: missing IP",
			zap.String("trace_id", finding.TraceID),
			zap.String("host", finding.Host),
		)
		return nil
	}

	// Process the discovery (asset_type is now in the finding)
	return s.processDiscovery(ctx, finding, finding.AssetType)
}

// processDiscovery processes a domain/subdomain discovery and stores in discoveries collection
func (s *Service) processDiscovery(ctx context.Context, finding shared.DiscoveryFinding, assetType string) error {
	now := time.Now()

	// 1. Upsert domain/subdomain in discoveries collection (with org_id)
	discoveryID, err := s.upsertDomainDiscovery(ctx, finding, assetType, now)
	if err != nil {
		return err
	}

	// 2. Upsert IP discovery (separate record with org_id)
	ipDiscoveryID, isNewIP, err := s.upsertIPDiscovery(ctx, finding, discoveryID, now)
	if err != nil {
		return err
	}

	// 3. Trigger port discovery if this is a new IP
	if isNewIP {
		if err := s.publishIPDiscoveryJob(ctx, finding, ipDiscoveryID); err != nil {
			s.logger.Error("Failed to publish IP discovery job",
				zap.String("trace_id", finding.TraceID),
				zap.String("ip", *finding.IP),
				zap.Error(err),
			)
			// Don't fail if trigger fails
		} else {
			s.logger.Info("Triggered IP discovery job",
				zap.String("trace_id", finding.TraceID),
				zap.String("ip", *finding.IP),
				zap.String("ip_discovery_id", ipDiscoveryID),
			)
		}
	}

	return nil
}

// upsertDomainDiscovery creates or updates a domain/subdomain discovery
func (s *Service) upsertDomainDiscovery(ctx context.Context, finding shared.DiscoveryFinding, assetType string, timestamp time.Time) (string, error) {
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Build filter based on org_id and asset type (org-scoped deduplication)
	filter := bson.M{
		"org_id":     finding.OrgID,
		"asset_type": assetType,
	}
	if assetType == shared.AssetTypeDomain {
		filter["domain"] = finding.Host
	} else {
		filter["subdomain"] = finding.Host
	}

	var existingDiscovery shared.Discovery
	err := collection.FindOne(ctx, filter).Decode(&existingDiscovery)

	if err == mongo.ErrNoDocuments {
		// Create new discovery using the deterministic ID from the finding
		// Initialize scan_ids array
		scanIDs := []string{}
		if finding.ScanID != nil {
			scanIDs = []string{*finding.ScanID}
		}

		newDiscovery := shared.Discovery{
			ID:             finding.DiscoveryID,                // Use provided deterministic ID (org-scoped)
			OrgID:          finding.OrgID,                      // Organization GUID
			ScanIDs:        scanIDs,                            // Array of scan identifiers
			AssetType:      assetType,
			Source:         finding.Source,
			Status:         finding.Status,
			OwnershipStatus: shared.OwnershipStatusVerified,     // Default to verified
			AssignedAt:     timestamp,                          // When assigned to org
			ParentID:       finding.ParentID,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			Metadata:       finding.Metadata,
			ResolutionHistory: []shared.ResolutionHistoryEntry{
				{
					IP:        *finding.IP,
					FirstSeen: timestamp,
					LastSeen:  nil, // Currently active
				},
			},
		}

		// Set domain or subdomain field
		if assetType == shared.AssetTypeDomain {
			newDiscovery.Domain = &finding.Host
		} else {
			newDiscovery.Subdomain = &finding.Host
		}

		doc := s.buildDiscoveryDocument(newDiscovery)

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create discovery",
				zap.String("asset_type", assetType),
				zap.String("host", finding.Host),
				zap.Error(err),
			)
			return "", err
		}

		s.logger.Info("Created new discovery",
			zap.String("discovery_id", finding.DiscoveryID),
			zap.String("asset_type", assetType),
			zap.String("host", finding.Host),
			zap.String("ip", *finding.IP),
		)
		return finding.DiscoveryID, nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing discovery",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", err
	}

	// Discovery exists - update resolution history
	if err := s.updateResolutionHistory(ctx, &existingDiscovery, finding, *finding.IP, timestamp); err != nil {
		return "", err
	}

	return existingDiscovery.ID, nil
}

// updateResolutionHistory updates the IP resolution history for a domain/subdomain
func (s *Service) updateResolutionHistory(ctx context.Context, discovery *shared.Discovery, finding shared.DiscoveryFinding, newIP string, timestamp time.Time) error {
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Check if IP has changed
	if len(discovery.ResolutionHistory) > 0 {
		lastResolution := discovery.ResolutionHistory[len(discovery.ResolutionHistory)-1]

		// If IP unchanged, just update last_seen and add scan_id to array
		if lastResolution.IP == newIP && lastResolution.LastSeen == nil {
			update := bson.M{
				"$set": bson.M{
					"last_seen": timestamp,
				},
			}
			// Add scan_id to array if present
			if finding.ScanID != nil {
				update["$addToSet"] = bson.M{
					"scan_ids": *finding.ScanID,
				}
			}
			_, err := collection.UpdateOne(ctx, bson.M{"_id": discovery.ID}, update)
			if err != nil {
				s.logger.Error("Failed to update discovery last_seen",
					zap.String("discovery_id", discovery.ID),
					zap.Error(err),
				)
				return err
			}

			s.logger.Debug("IP unchanged, updated last_seen",
				zap.String("discovery_id", discovery.ID),
				zap.String("ip", newIP),
			)
			return nil
		}

		// If IP changed, close previous resolution and add new one
		if lastResolution.IP != newIP && lastResolution.LastSeen == nil {
			update := bson.M{
				"$set": bson.M{
					"resolution_history." + fmt.Sprint(len(discovery.ResolutionHistory)-1) + ".last_seen": timestamp,
					"last_seen": timestamp,
				},
				"$push": bson.M{
					"resolution_history": shared.ResolutionHistoryEntry{
						IP:        newIP,
						FirstSeen: timestamp,
						LastSeen:  nil, // Currently active
					},
				},
			}
			// Add scan_id to array if present
			if finding.ScanID != nil {
				update["$addToSet"] = bson.M{
					"scan_ids": *finding.ScanID,
				}
			}

			_, err := collection.UpdateOne(ctx, bson.M{"_id": discovery.ID}, update)
			if err != nil {
				s.logger.Error("Failed to update resolution history",
					zap.String("discovery_id", discovery.ID),
					zap.Error(err),
				)
				return err
			}

			s.logger.Info("Updated discovery with new IP resolution",
				zap.String("discovery_id", discovery.ID),
				zap.String("old_ip", lastResolution.IP),
				zap.String("new_ip", newIP),
			)
			return nil
		}
	}

	// Shouldn't reach here, but handle gracefully
	update := bson.M{
		"$push": bson.M{
			"resolution_history": shared.ResolutionHistoryEntry{
				IP:        newIP,
				FirstSeen: timestamp,
				LastSeen:  nil,
			},
		},
		"$set": bson.M{
			"last_seen": timestamp,
		},
	}
	// Add scan_id to array if present
	if finding.ScanID != nil {
		update["$addToSet"] = bson.M{
			"scan_ids": *finding.ScanID,
		}
	}

	_, err := collection.UpdateOne(ctx, bson.M{"_id": discovery.ID}, update)
	if err != nil {
		s.logger.Error("Failed to add resolution history",
			zap.String("discovery_id", discovery.ID),
			zap.Error(err),
		)
		return err
	}

	return nil
}

// upsertIPDiscovery creates or updates an IP discovery
// Returns (ipDiscoveryID, isNewIP, error)
func (s *Service) upsertIPDiscovery(ctx context.Context, finding shared.DiscoveryFinding, parentDiscoveryID string, timestamp time.Time) (string, bool, error) {
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Check if IP discovery already exists (org-scoped)
	filter := bson.M{
		"org_id":     finding.OrgID,
		"asset_type": shared.AssetTypeIP,
		"ip":         *finding.IP,
	}

	var existingIPDiscovery shared.Discovery
	err := collection.FindOne(ctx, filter).Decode(&existingIPDiscovery)

	if err == mongo.ErrNoDocuments {
		// Create new IP discovery using deterministic ID (org-scoped)
		ipDiscoveryID := shared.GenerateIPID(finding.OrgID, *finding.IP)
		// Initialize scan_ids array
		scanIDs := []string{}
		if finding.ScanID != nil {
			scanIDs = []string{*finding.ScanID}
		}

		// IP geolocation enrichment now handled by discovery_enrichment service
		var metadata map[string]interface{}

		newIPDiscovery := shared.Discovery{
			ID:             ipDiscoveryID,
			OrgID:          finding.OrgID,                   // Organization GUID
			ScanIDs:        scanIDs,                         // Array of scan identifiers
			AssetType:      shared.AssetTypeIP,
			Source:         finding.Source,
			Status:         finding.Status,
			OwnershipStatus: shared.OwnershipStatusVerified,  // Default to verified
			AssignedAt:     timestamp,                       // When assigned to org
			ParentID:       &parentDiscoveryID,
			IP:             finding.IP,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			Metadata:       metadata,                        // Use enriched metadata
		}

		doc := s.buildDiscoveryDocument(newIPDiscovery)

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create IP discovery",
				zap.String("ip", *finding.IP),
				zap.Error(err),
			)
			return "", false, err
		}

		s.logger.Info("Created new IP discovery",
			zap.String("discovery_id", ipDiscoveryID),
			zap.String("ip", *finding.IP),
			zap.String("parent_id", parentDiscoveryID),
		)
		return ipDiscoveryID, true, nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing IP discovery",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", false, err
	}

	// IP exists - just update last_seen and add scan_id to array
	update := bson.M{
		"$set": bson.M{
			"last_seen": timestamp,
		},
	}
	// Add scan_id to array if present
	if finding.ScanID != nil {
		update["$addToSet"] = bson.M{
			"scan_ids": *finding.ScanID,
		}
	}

	_, err = collection.UpdateOne(ctx, bson.M{"_id": existingIPDiscovery.ID}, update)
	if err != nil {
		s.logger.Error("Failed to update IP discovery",
			zap.String("ip", *finding.IP),
			zap.Error(err),
		)
		return "", false, err
	}

	s.logger.Debug("Updated existing IP discovery",
		zap.String("discovery_id", existingIPDiscovery.ID),
		zap.String("ip", *finding.IP),
	)
	return existingIPDiscovery.ID, false, nil
}

// publishIPDiscoveryJob publishes an IP discovery job to trigger port scanning
func (s *Service) publishIPDiscoveryJob(ctx context.Context, finding shared.DiscoveryFinding, ipDiscoveryID string) error {
	ipJob := shared.IPDiscoveryJob{
		TraceID:  finding.TraceID,
		ScanID:   finding.ScanID,                        // Pass through scan_id
		OrgID:    finding.OrgID,
		ParentID: &ipDiscoveryID,
		IP:       *finding.IP,
		Metadata: map[string]interface{}{
			"source":          "domain_discovery",
			"ip_discovery_id": ipDiscoveryID,
		},
		Created: time.Now(),
	}

	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamIPDiscoveryQueue, ipJob); err != nil {
		return fmt.Errorf("failed to publish IP discovery job: %w", err)
	}

	return nil
}

// buildDiscoveryDocument builds a BSON document from a Discovery struct, excluding nil fields
func (s *Service) buildDiscoveryDocument(discovery shared.Discovery) bson.M {
	doc := bson.M{
		"_id":              discovery.ID,
		"org_id":           discovery.OrgID,
		"asset_type":       discovery.AssetType,
		"source":           discovery.Source,
		"status":           discovery.Status,
		"ownership_status": discovery.OwnershipStatus,
		"assigned_at":      discovery.AssignedAt,
		"first_seen":       discovery.FirstSeen,
		"last_seen":        discovery.LastSeen,
	}

	if len(discovery.ScanIDs) > 0 {
		doc["scan_ids"] = discovery.ScanIDs
	}

	if discovery.ParentID != nil {
		doc["parent_id"] = discovery.ParentID
	}

	if len(discovery.Metadata) > 0 {
		doc["metadata"] = discovery.Metadata
	}

	// Asset-type specific fields
	if discovery.Domain != nil {
		doc["domain"] = discovery.Domain
	}
	if discovery.Subdomain != nil {
		doc["subdomain"] = discovery.Subdomain
	}
	if discovery.IP != nil {
		doc["ip"] = discovery.IP
	}
	if len(discovery.ResolutionHistory) > 0 {
		doc["resolution_history"] = discovery.ResolutionHistory
	}

	return doc
}
