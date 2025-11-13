package enrichment_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Service handles enrichment ingestion and MongoDB updates
type Service struct {
	db     *mongo.Database
	redis  *redis.Client
	logger *zap.Logger
}

// NewService creates a new enrichment ingestion service
func NewService(db *mongo.Database, redis *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

// ProcessEnrichment processes an enrichment finding and updates the discovery in MongoDB
func (s *Service) ProcessEnrichment(ctx context.Context, enrichment shared.EnrichmentFinding) error {
	s.logger.Info("Processing enrichment finding",
		zap.String("trace_id", enrichment.TraceID),
		zap.String("org_id", enrichment.OrgID),
		zap.String("source", enrichment.Scanner),
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("enrichment_type", enrichment.EnrichmentType),
	)

	// Validate source is present (required)
	if enrichment.Scanner == "" {
		s.logger.Warn("Skipping enrichment: missing source",
			zap.String("trace_id", enrichment.TraceID),
			zap.String("org_id", enrichment.OrgID),
			zap.String("discovery_id", enrichment.DiscoveryID),
		)
		return nil
	}

	// Validate discovery_id is present
	if enrichment.DiscoveryID == "" {
		s.logger.Warn("Skipping enrichment: missing discovery_id",
			zap.String("trace_id", enrichment.TraceID),
			zap.String("org_id", enrichment.OrgID),
		)
		return nil
	}

	// Update discovery based on enrichment type
	switch enrichment.EnrichmentType {
	case "waf":
		return s.processWAFEnrichment(ctx, enrichment)
	case "geolocation":
		return s.processGeolocationEnrichment(ctx, enrichment)
	case "cloud":
		return s.processCloudEnrichment(ctx, enrichment)
	default:
		s.logger.Warn("Unknown enrichment type",
			zap.String("enrichment_type", enrichment.EnrichmentType),
		)
		return nil
	}
}

// processWAFEnrichment processes WAF enrichment data
func (s *Service) processWAFEnrichment(ctx context.Context, enrichment shared.EnrichmentFinding) error {
	// Extract WAF name from enrichment data
	wafName, ok := enrichment.Data["waf_name"].(string)
	if !ok || wafName == "" {
		s.logger.Warn("Invalid WAF enrichment data: missing waf_name",
			zap.String("discovery_id", enrichment.DiscoveryID),
		)
		return nil
	}

	s.logger.Info("Updating discovery with WAF information",
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("waf_name", wafName),
	)

	// Update discovery in MongoDB
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Build update document
	// Simply set metadata.waf to the WAF name (overwrites any previous value)
	update := bson.M{
		"$set": bson.M{
			"metadata.waf": wafName,
			"last_seen":    time.Now(),
		},
	}

	// Add scan_id to scan_ids array if present (using $addToSet to avoid duplicates)
	if enrichment.ScanID != nil && *enrichment.ScanID != "" {
		update["$addToSet"] = bson.M{
			"scan_ids": *enrichment.ScanID,
		}
	}

	// Update by discovery_id and org_id (for security)
	filter := bson.M{
		"_id":    enrichment.DiscoveryID,
		"org_id": enrichment.OrgID,
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update discovery: %w", err)
	}

	if result.MatchedCount == 0 {
		s.logger.Warn("Discovery not found for enrichment",
			zap.String("discovery_id", enrichment.DiscoveryID),
			zap.String("org_id", enrichment.OrgID),
		)
		return nil
	}

	s.logger.Info("Successfully updated discovery with WAF enrichment",
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("waf_name", wafName),
		zap.Int64("modified_count", result.ModifiedCount),
	)

	return nil
}

// processGeolocationEnrichment processes IP geolocation enrichment data
func (s *Service) processGeolocationEnrichment(ctx context.Context, enrichment shared.EnrichmentFinding) error {
	// Extract geolocation data from enrichment
	continent, _ := enrichment.Data["continent"].(string)
	country, _ := enrichment.Data["country"].(string)
	isp, _ := enrichment.Data["isp"].(string)

	s.logger.Info("Updating discovery with geolocation information",
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("continent", continent),
		zap.String("country", country),
		zap.String("isp", isp),
	)

	// Update discovery in MongoDB
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Build update document
	// Set geolocation metadata fields (nested under metadata.geo)
	setFields := bson.M{
		"last_seen": time.Now(),
	}

	// Only set fields that have values (nested under metadata.geo)
	if continent != "" {
		setFields["metadata.geo.continent"] = continent
	}
	if country != "" {
		setFields["metadata.geo.country"] = country
	}
	if isp != "" {
		setFields["metadata.geo.isp"] = isp
	}

	update := bson.M{
		"$set": setFields,
	}

	// Add scan_id to scan_ids array if present (using $addToSet to avoid duplicates)
	if enrichment.ScanID != nil && *enrichment.ScanID != "" {
		update["$addToSet"] = bson.M{
			"scan_ids": *enrichment.ScanID,
		}
	}

	// Update by discovery_id and org_id (for security)
	filter := bson.M{
		"_id":    enrichment.DiscoveryID,
		"org_id": enrichment.OrgID,
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update discovery: %w", err)
	}

	if result.MatchedCount == 0 {
		s.logger.Warn("Discovery not found for enrichment",
			zap.String("discovery_id", enrichment.DiscoveryID),
			zap.String("org_id", enrichment.OrgID),
		)
		return nil
	}

	s.logger.Info("Successfully updated discovery with geolocation enrichment",
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("continent", continent),
		zap.String("country", country),
		zap.String("isp", isp),
		zap.Int64("modified_count", result.ModifiedCount),
	)

	return nil
}

// processCloudEnrichment processes cloud provider enrichment data
func (s *Service) processCloudEnrichment(ctx context.Context, enrichment shared.EnrichmentFinding) error {
	// Extract cloud provider data from enrichment
	provider, _ := enrichment.Data["provider"].(string)
	region, _ := enrichment.Data["region"].(string)
	service, _ := enrichment.Data["service"].(string)

	s.logger.Info("Updating discovery with cloud provider information",
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("provider", provider),
		zap.String("region", region),
		zap.String("service", service),
	)

	// Update discovery in MongoDB
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Build update document
	// Set cloud metadata fields (nested under metadata.cloud)
	setFields := bson.M{
		"last_seen": time.Now(),
	}

	// Only set fields that have values (nested under metadata.cloud)
	if provider != "" {
		setFields["metadata.cloud.provider"] = provider
	}
	if region != "" {
		setFields["metadata.cloud.region"] = region
	}
	if service != "" {
		setFields["metadata.cloud.service"] = service
	}

	update := bson.M{
		"$set": setFields,
	}

	// Add scan_id to scan_ids array if present (using $addToSet to avoid duplicates)
	if enrichment.ScanID != nil && *enrichment.ScanID != "" {
		update["$addToSet"] = bson.M{
			"scan_ids": *enrichment.ScanID,
		}
	}

	// Update by discovery_id and org_id (for security)
	filter := bson.M{
		"_id":    enrichment.DiscoveryID,
		"org_id": enrichment.OrgID,
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update discovery: %w", err)
	}

	if result.MatchedCount == 0 {
		s.logger.Warn("Discovery not found for enrichment",
			zap.String("discovery_id", enrichment.DiscoveryID),
			zap.String("org_id", enrichment.OrgID),
		)
		return nil
	}

	s.logger.Info("Successfully updated discovery with cloud enrichment",
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("provider", provider),
		zap.String("region", region),
		zap.String("service", service),
		zap.Int64("modified_count", result.ModifiedCount),
	)

	return nil
}
