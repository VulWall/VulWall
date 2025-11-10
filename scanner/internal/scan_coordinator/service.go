package scan_coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Service handles scan coordination logic
type Service struct {
	redis  *redis.Client
	db     *mongo.Database
	logger *zap.Logger
}

// NewService creates a new scan coordinator service
func NewService(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		db:     db,
		logger: logger,
	}
}

// ProcessOrganization checks if an organization needs a scan and triggers it
func (s *Service) ProcessOrganization(ctx context.Context, org shared.Organization) error {
	s.logger.Info("Processing organization for scheduled scan",
		zap.String("org_id", org.ID),
		zap.String("company_name", org.CompanyName),
		zap.Int("scan_interval_days", org.SubscriptionSettings.ScanIntervalDays),
	)

	// Get the most recent scan for this organization
	lastScan, err := s.getLastScan(ctx, org.ID)
	if err != nil && err != mongo.ErrNoDocuments {
		return fmt.Errorf("failed to get last scan: %w", err)
	}

	// Determine if we need to trigger a new scan
	needsScan := false
	if lastScan == nil {
		// No previous scan exists
		s.logger.Info("No previous scan found, triggering initial scan", zap.String("org_id", org.ID))
		needsScan = true
	} else {
		// Check if enough time has passed since last scan
		daysSinceLastScan := time.Since(lastScan.CreatedAt).Hours() / 24
		if int(daysSinceLastScan) >= org.SubscriptionSettings.ScanIntervalDays {
			s.logger.Info("Scan interval elapsed, triggering new scan",
				zap.String("org_id", org.ID),
				zap.Float64("days_since_last_scan", daysSinceLastScan),
				zap.Int("scan_interval_days", org.SubscriptionSettings.ScanIntervalDays),
			)
			needsScan = true
		} else {
			s.logger.Debug("Scan interval not yet elapsed, skipping",
				zap.String("org_id", org.ID),
				zap.Float64("days_since_last_scan", daysSinceLastScan),
				zap.Int("scan_interval_days", org.SubscriptionSettings.ScanIntervalDays),
			)
		}
	}

	if !needsScan {
		return nil
	}

	// Create new scan record
	scanID := uuid.New().String()
	scan := shared.Scan{
		ID:          scanID,
		OrgID:       org.ID,
		Status:      shared.StatusPending,
		Type:        shared.ScanTypeScheduled,
		TriggeredBy: "system",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Insert scan into database
	if err := s.createScan(ctx, scan); err != nil {
		return fmt.Errorf("failed to create scan: %w", err)
	}

	s.logger.Info("Created new scan record",
		zap.String("scan_id", scanID),
		zap.String("org_id", org.ID),
	)

	// Get all assets for this organization
	assets, err := s.getOrgAssets(ctx, org.ID)
	if err != nil {
		return fmt.Errorf("failed to get org assets: %w", err)
	}

	s.logger.Info("Found assets to scan",
		zap.String("org_id", org.ID),
		zap.Int("asset_count", len(assets)),
	)

	// Publish discovery jobs for each asset
	if err := s.publishDiscoveryJobs(ctx, org.ID, scanID, assets); err != nil {
		return fmt.Errorf("failed to publish discovery jobs: %w", err)
	}

	s.logger.Info("Successfully triggered scan",
		zap.String("scan_id", scanID),
		zap.String("org_id", org.ID),
		zap.Int("jobs_published", len(assets)),
	)

	return nil
}

// getLastScan retrieves the most recent scan for an organization
func (s *Service) getLastScan(ctx context.Context, orgID string) (*shared.Scan, error) {
	coll := s.db.Collection(shared.CollectionScans)

	var scan shared.Scan
	err := coll.FindOne(ctx, bson.M{
		"org_id": orgID,
	}, nil).Decode(&scan)

	if err != nil {
		return nil, err
	}

	return &scan, nil
}

// createScan inserts a new scan record into the database
func (s *Service) createScan(ctx context.Context, scan shared.Scan) error {
	coll := s.db.Collection(shared.CollectionScans)
	_, err := coll.InsertOne(ctx, scan)
	return err
}

// getOrgAssets retrieves all active user-added assets for an organization
func (s *Service) getOrgAssets(ctx context.Context, orgID string) ([]shared.Asset, error) {
	coll := s.db.Collection(shared.CollectionAssets)

	// Query for all active assets (user-added assets to be scanned)
	filter := bson.M{
		"org_id": orgID,
		"status": "Active",
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var assets []shared.Asset
	if err := cursor.All(ctx, &assets); err != nil {
		return nil, err
	}

	return assets, nil
}

// publishDiscoveryJobs publishes discovery jobs to Redis for each asset
func (s *Service) publishDiscoveryJobs(ctx context.Context, orgID, scanID string, assets []shared.Asset) error {
	traceID := uuid.New().String()

	for _, asset := range assets {
		switch asset.Type {
		case "domain":
			// Publish domain discovery job
			if asset.Domain == nil {
				s.logger.Warn("Domain asset missing domain field",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
				)
				continue
			}

			job := shared.DiscoveryJob{
				TraceID: traceID,
				ScanID:  &scanID,
				OrgID:   orgID,
				Host:    *asset.Domain,
				Created: time.Now(),
			}

			if err := s.publishToStream(ctx, shared.StreamDomainDiscoveryQueue, job); err != nil {
				s.logger.Error("Failed to publish domain discovery job",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
					zap.Error(err),
				)
				continue
			}

			s.logger.Debug("Published domain discovery job",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("host", *asset.Domain),
			)

		case "ip":
			// Publish IP discovery job (port scanning)
			if asset.IP == nil {
				s.logger.Warn("IP asset missing IP field",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
				)
				continue
			}

			job := shared.IPDiscoveryJob{
				TraceID: traceID,
				ScanID:  &scanID,
				OrgID:   orgID,
				IP:      *asset.IP,
				Created: time.Now(),
			}

			if err := s.publishToStream(ctx, shared.StreamIPDiscoveryQueue, job); err != nil {
				s.logger.Error("Failed to publish IP discovery job",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
					zap.Error(err),
				)
				continue
			}

			s.logger.Debug("Published IP discovery job",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("ip", *asset.IP),
			)

		default:
			s.logger.Warn("Unknown asset type",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("type", asset.Type),
			)
		}
	}

	return nil
}

// publishToStream publishes a job to a Redis stream
func (s *Service) publishToStream(ctx context.Context, stream string, job interface{}) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	_, err = s.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: stream,
		Values: map[string]interface{}{
			"data": string(data),
		},
	}).Result()

	return err
}
