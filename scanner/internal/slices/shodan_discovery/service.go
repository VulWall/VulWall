package shodan_discovery

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"github.com/vulwall/scanners/internal/slices/shodan_discovery/shodan"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type Service struct {
	db           *mongo.Database
	logger       *zap.Logger
	shodanClient *shodan.Client
}

func NewService(db *mongo.Database, shodanAPIKey string, logger *zap.Logger) *Service {
	return &Service{
		db:           db,
		logger:       logger,
		shodanClient: shodan.NewClient(shodanAPIKey, logger),
	}
}

// ProcessJob processes a discovery job using Shodan
func (s *Service) ProcessJob(ctx context.Context, job shared.DiscoveryJob) error {
	s.logger.Info("Processing discovery job with Shodan",
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
	asset := &shared.AttackSurfaceAsset{
		ID:        uuid.New().String(),
		ParentID:  job.ParentID,
		Host:      job.Host,
		Port:      job.Port,
		Protocol:  job.Protocol,
		Status:    shared.AssetStatusActive,
		FirstSeen: now,
		LastSeen:  now,
		Metadata:  job.Metadata,
	}

	if err := s.createAsset(ctx, asset); err != nil {
		return err
	}

	// Trigger Shodan subdomain discovery for root domains (no parent, no port)
	if job.ParentID == nil && job.Port == nil && s.isDomain(job.Host) {
		go func() {
			if err := s.discoverSubdomains(context.Background(), asset.ID, job.Host); err != nil {
				s.logger.Error("Shodan discovery failed",
					zap.String("asset_id", asset.ID),
					zap.String("host", job.Host),
					zap.Error(err),
				)
			}
		}()
	}

	return nil
}

// discoverSubdomains uses Shodan to discover and create subdomain assets
func (s *Service) discoverSubdomains(ctx context.Context, parentID, domain string) error {
	s.logger.Info("Starting Shodan subdomain discovery",
		zap.String("parent_id", parentID),
		zap.String("domain", domain),
	)

	// Discover subdomains using Shodan
	subdomains, err := s.shodanClient.DiscoverSubdomains(ctx, domain)
	if err != nil {
		return err
	}

	if len(subdomains) == 0 {
		s.logger.Info("No subdomains discovered", zap.String("domain", domain))
		return nil
	}

	now := time.Now()

	// Create or update each discovered subdomain
	for _, subdomainName := range subdomains {
		// Skip empty strings and wildcards
		if subdomainName == "" || subdomainName == "*" {
			continue
		}

		// Build the full subdomain
		fullSubdomain := subdomainName
		if !contains(subdomainName, domain) {
			fullSubdomain = subdomainName + "." + domain
		}

		// Check if subdomain already exists
		existing, err := s.findExistingAsset(ctx, fullSubdomain, nil, nil)
		if err != nil {
			s.logger.Error("Failed to check existing subdomain",
				zap.String("subdomain", fullSubdomain),
				zap.Error(err),
			)
			continue
		}

		if existing != nil {
			// Update last_seen
			metadata := map[string]interface{}{"source": "shodan"}
			if err := s.updateAssetLastSeen(ctx, existing.ID, now, metadata); err != nil {
				s.logger.Error("Failed to update subdomain last_seen",
					zap.String("subdomain", fullSubdomain),
					zap.Error(err),
				)
			}
			continue
		}

		// Create new subdomain asset
		assetID := uuid.New().String()
		asset := &shared.AttackSurfaceAsset{
			ID:        assetID,
			ParentID:  &parentID,
			Host:      fullSubdomain,
			Port:      nil,
			Protocol:  nil,
			Status:    shared.AssetStatusActive,
			FirstSeen: now,
			LastSeen:  now,
			Metadata:  map[string]interface{}{"source": "shodan"},
		}

		if err := s.createAsset(ctx, asset); err != nil {
			s.logger.Error("Failed to create subdomain asset",
				zap.String("subdomain", fullSubdomain),
				zap.Error(err),
			)
			continue
		}

		s.logger.Info("Created subdomain asset",
			zap.String("asset_id", assetID),
			zap.String("subdomain", fullSubdomain),
		)
	}

	return nil
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

// isDomain checks if the host is a domain (simple heuristic)
func (s *Service) isDomain(host string) bool {
	// Simple heuristic: if it contains only numbers and dots, it's an IP
	for _, c := range host {
		if !(c >= '0' && c <= '9' || c == '.') {
			return true
		}
	}
	return false
}

// contains checks if a string contains a substring (for subdomain building)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[len(s)-len(substr)-1:] == "."+substr || s[:len(substr)+1] == substr+"."))
}
