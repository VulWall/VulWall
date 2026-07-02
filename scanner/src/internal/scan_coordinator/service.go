package scan_coordinator

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ErrOrgNotFound indicates a scan was requested for an organization that no
// longer exists — e.g., deleted between a cron enqueue and execution, or a bad
// API caller. Callers should surface this as a 404, not a 500.
var ErrOrgNotFound = errors.New("organization not found")

// Service handles scan coordination logic
type Service struct {
	redis  *redis.Client
	db     *mongo.Database
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new scan coordinator service
func NewService(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		db:     db,
		logger: logger,
		tracer: otel.Tracer("scan-coordinator"),
	}
}

// ScanRequest represents a request to trigger a scan for an organization.
type ScanRequest struct {
	OrgID       string // Organization GUID
	Type        string // "scheduled", "requested"
	TriggeredBy string // "system" or user ID
}

// TriggerScan creates a scan record and publishes discovery jobs for an organization.
// Returns the scan ID on success.
func (s *Service) TriggerScan(ctx context.Context, req ScanRequest) (string, error) {
	ctx, span := s.tracer.Start(ctx, "trigger_scan",
		trace.WithAttributes(
			attribute.String("org.id", req.OrgID),
		),
	)
	defer span.End()

	s.logger.Info("Triggering scan for organization",
		zap.String("org_id", req.OrgID),
		zap.String("type", req.Type),
		zap.String("triggered_by", req.TriggeredBy),
	)

	// Verify the org still exists before creating a scan record or publishing
	// jobs. A stale cron entry or a bad API caller could otherwise create an
	// orphan scan for a deleted org. See NightWatch #167.
	exists, err := s.orgExists(ctx, req.OrgID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to verify organization: %w", err)
	}
	if !exists {
		span.SetStatus(codes.Error, ErrOrgNotFound.Error())
		s.logger.Warn("Skipping scan trigger: organization not found",
			zap.String("org_id", req.OrgID),
		)
		return "", ErrOrgNotFound
	}

	// Get all assets for this organization first (needed for targeted_assets)
	assets, err := s.getOrgAssets(ctx, req.OrgID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to get org assets: %w", err)
	}

	s.logger.Info("Found assets to scan",
		zap.String("org_id", req.OrgID),
		zap.Int("asset_count", len(assets)),
	)

	// Build targeted assets array for audit trail
	targetedAssets := make([]shared.AssetTarget, 0, len(assets))
	for _, asset := range assets {
		target := shared.AssetTarget{
			AssetID: asset.ID,
			Type:    asset.Type,
		}

		// Set the value based on asset type
		if asset.Type == "domain" && asset.Domain != nil {
			target.Value = *asset.Domain
		} else if asset.Type == "ip" && asset.IP != nil {
			target.Value = *asset.IP
		} else {
			// Skip assets with missing values
			s.logger.Warn("Asset missing required field, skipping from targeted assets",
				zap.String("org_id", req.OrgID),
				zap.String("asset_id", asset.ID),
				zap.String("type", asset.Type),
			)
			continue
		}

		targetedAssets = append(targetedAssets, target)
	}

	// Create new scan record with targeted assets
	scanID := uuid.New().String()
	scan := shared.Scan{
		ID:             scanID,
		OrgID:          req.OrgID,
		Status:         shared.StatusRunning,
		Type:           req.Type,
		TriggeredBy:    req.TriggeredBy,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		TargetedAssets: targetedAssets,
		Stats: shared.ScanStats{
			TotalAssets: len(targetedAssets),
		},
	}

	// Insert scan into database
	if err := s.createScan(ctx, scan); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to create scan: %w", err)
	}

	span.SetAttributes(attribute.String("scan.id", scanID))

	s.logger.Info("Created new scan record",
		zap.String("scan_id", scanID),
		zap.String("org_id", req.OrgID),
		zap.Int("targeted_assets_count", len(targetedAssets)),
	)

	// Publish discovery jobs for each asset
	if err := s.publishDiscoveryJobs(ctx, req.OrgID, scanID, assets); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to publish discovery jobs: %w", err)
	}

	span.SetStatus(codes.Ok, "")

	s.logger.Info("Successfully triggered scan",
		zap.String("scan_id", scanID),
		zap.String("org_id", req.OrgID),
		zap.Int("jobs_published", len(assets)),
	)

	return scanID, nil
}

// createScan inserts a new scan record into the database
func (s *Service) createScan(ctx context.Context, scan shared.Scan) error {
	coll := s.db.Collection(shared.CollectionScans)
	_, err := coll.InsertOne(ctx, scan)
	return err
}

// orgExists reports whether an organization document exists for orgID.
// Mirrors the org-collection access pattern used by the scheduler.
func (s *Service) orgExists(ctx context.Context, orgID string) (bool, error) {
	coll := s.db.Collection(shared.CollectionOrganizations)
	err := coll.FindOne(ctx, bson.M{"_id": orgID}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// getOrgAssets retrieves all enabled user-added assets for an organization
func (s *Service) getOrgAssets(ctx context.Context, orgID string) ([]shared.Asset, error) {
	coll := s.db.Collection(shared.CollectionAssets)

	// Query for all enabled assets (user-added assets to be scanned)
	filter := bson.M{
		"org_id":  orgID,
		"enabled": true,
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
	ctx, span := s.tracer.Start(ctx, "publish_discovery_jobs")
	defer span.End()

	traceID := uuid.New().String()

	domainCount := 0
	ipCount := 0

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

			// Sanitize domain to strip URL scheme (https://) and paths
			host := sanitizeDomain(*asset.Domain)

			job := shared.DiscoveryJob{
				TraceID:      traceID,
				TraceContext: telemetry.InjectTraceContext(ctx), // Inject trace context for distributed tracing
				ScanID:       &scanID,
				OrgID:        orgID,
				Host:         host,
				Created:      time.Now(),
			}

			// Publish to job queue WITHOUT MAXLEN (queues should not be trimmed)
			if err := redisx.PublishToStream(ctx, s.redis, shared.StreamDomainDiscoveryQueue, job, 0); err != nil {
				s.logger.Error("Failed to publish domain discovery job",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
					zap.Error(err),
				)
				continue
			}

			domainCount++

			s.logger.Debug("Published domain discovery job",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("host", host),
				zap.String("original", *asset.Domain),
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
				TraceID:      traceID,
				TraceContext: telemetry.InjectTraceContext(ctx), // Inject trace context for distributed tracing
				ScanID:       &scanID,
				OrgID:        orgID,
				IP:           *asset.IP,
				Created:      time.Now(),
			}

			// Publish to job queue WITHOUT MAXLEN (queues should not be trimmed)
			if err := redisx.PublishToStream(ctx, s.redis, shared.StreamIPDiscoveryQueue, job, 0); err != nil {
				s.logger.Error("Failed to publish IP discovery job",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
					zap.Error(err),
				)
				continue
			}

			ipCount++

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

	span.SetAttributes(
		attribute.Int("jobs.domain_count", domainCount),
		attribute.Int("jobs.ip_count", ipCount),
		attribute.Int("jobs.total_count", domainCount+ipCount),
	)

	span.SetStatus(codes.Ok, "")

	return nil
}

// sanitizeDomain extracts the hostname from a domain string, stripping any URL scheme or path.
// Examples: "https://example.com" -> "example.com", "example.com/path" -> "example.com"
func sanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)

	// If it looks like a URL (has scheme), parse it
	if strings.Contains(domain, "://") {
		if parsed, err := url.Parse(domain); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}

	// Strip any path component
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}

	return domain
}
