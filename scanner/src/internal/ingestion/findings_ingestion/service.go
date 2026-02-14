package findings_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// AllowedSeveritiesForAI defines which severity levels trigger AI enrichment
var AllowedSeveritiesForAI = map[string]bool{
	shared.SeverityCritical: true,
	shared.SeverityHigh:     true,
	shared.SeverityMedium:   true,
}

// Service handles persistence of security findings to MongoDB
type Service struct {
	db     *mongo.Database
	redis  *redis.Client
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new findings ingestion service
func NewService(db *mongo.Database, redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redisClient,
		logger: logger,
		tracer: otel.Tracer("findings-ingestion"),
	}
}

// ProcessFinding processes a security finding and persists it to MongoDB
func (s *Service) ProcessFinding(ctx context.Context, finding shared.SecurityFinding) error {
	ctx, span := s.tracer.Start(ctx, "ingest_security_finding",
		trace.WithAttributes(
			attribute.String("org.id", finding.OrgID),
			attribute.String("trace.id", finding.TraceID),
			attribute.String("finding.type", finding.FindingType),
			attribute.String("severity", finding.Severity),
		),
	)
	defer span.End()

	// Validate required fields
	if finding.Source == "" {
		s.logger.Warn("Skipping finding without source field")
		return nil
	}

	if finding.OrgID == "" {
		s.logger.Warn("Skipping finding without org_id")
		return nil
	}

	s.logger.Info("Processing security finding",
		zap.String("org_id", finding.OrgID),
		zap.String("source", finding.Source),
		zap.String("finding_type", finding.FindingType),
		zap.String("severity", finding.Severity),
		zap.String("title", finding.Title),
	)

	// Upsert the finding (deduplicate by org_id + discovery_id + finding_type + title)
	needsAIEnrichment, err := s.upsertFinding(ctx, finding)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to upsert finding: %w", err)
	}

	// Publish to AI enrichment queue if eligible (high/critical severity + not already enriched)
	if needsAIEnrichment {
		if err := s.publishAIEnrichmentJob(ctx, finding); err != nil {
			// Log error but don't fail the ingestion
			s.logger.Error("Failed to publish AI enrichment job",
				zap.String("org_id", finding.OrgID),
				zap.String("finding_type", finding.FindingType),
				zap.Error(err),
			)
		}
	}

	return nil
}

// upsertFinding creates or updates a finding in the findings collection
// Returns true if AI enrichment is needed (new finding with eligible severity and no existing AI recommendation)
func (s *Service) upsertFinding(ctx context.Context, finding shared.SecurityFinding) (bool, error) {
	collection := s.db.Collection(shared.CollectionFindings)

	// Check if finding already exists (deduplicate)
	filter := bson.M{
		"org_id":       finding.OrgID,
		"discovery_id": finding.DiscoveryID,
		"finding_type": finding.FindingType,
		"title":        finding.Title,
	}

	var existingFinding bson.M
	err := collection.FindOne(ctx, filter).Decode(&existingFinding)

	now := time.Now()

	if err == mongo.ErrNoDocuments {
		// Finding doesn't exist, create new one
		// Initialize scan_ids array
		scanIDs := []string{}
		if finding.ScanID != nil {
			scanIDs = []string{*finding.ScanID}
		}

		findingDoc := bson.M{
			"_id":            uuid.New().String(),
			"org_id":         finding.OrgID,
			"discovery_id":   finding.DiscoveryID,
			"finding_type":   finding.FindingType,
			"severity":       finding.Severity,
			"source":         finding.Source,
			"title":          finding.Title,
			"description":    finding.Description,
			"metadata":       finding.Metadata,
			"status":         finding.Status,
			"first_detected": now,
			"last_detected":  now,
		}

		// Add scan_ids array if present
		if len(scanIDs) > 0 {
			findingDoc["scan_ids"] = scanIDs
		}

		_, err := collection.InsertOne(ctx, findingDoc)
		if err != nil {
			return false, fmt.Errorf("failed to insert finding: %w", err)
		}

		s.logger.Info("Created new finding",
			zap.String("finding_id", findingDoc["_id"].(string)),
			zap.String("org_id", finding.OrgID),
			zap.String("finding_type", finding.FindingType),
		)

		// New finding - check if it needs AI enrichment (high/critical severity)
		needsAI := AllowedSeveritiesForAI[finding.Severity]
		return needsAI, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to query existing finding: %w", err)
	}

	// Finding exists, update last_detected and metadata
	findingID := existingFinding["_id"].(string)

	update := bson.M{
		"$set": bson.M{
			"last_detected": now,
			"metadata":      finding.Metadata,    // Update with latest metadata
			"severity":      finding.Severity,    // Update severity in case it changed
			"description":   finding.Description, // Update description
		},
	}

	// Add scan_id to array if present
	if finding.ScanID != nil {
		update["$addToSet"] = bson.M{
			"scan_ids": *finding.ScanID,
		}
	}

	// If finding was previously resolved, reopen it
	if status, ok := existingFinding["status"].(string); ok && status == shared.FindingStatusResolved {
		update["$set"].(bson.M)["status"] = shared.FindingStatusOpen
		update["$unset"] = bson.M{"resolved_at": ""}

		s.logger.Info("Reopening resolved finding",
			zap.String("finding_id", findingID),
			zap.String("finding_type", finding.FindingType),
		)
	}

	_, err = collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return false, fmt.Errorf("failed to update finding: %w", err)
	}

	s.logger.Info("Updated existing finding",
		zap.String("finding_id", findingID),
		zap.String("org_id", finding.OrgID),
		zap.String("finding_type", finding.FindingType),
	)

	// Check if existing finding needs AI enrichment:
	// - Has eligible severity AND doesn't already have ai_recommendation
	_, hasAIRecommendation := existingFinding["ai_recommendation"]
	needsAI := AllowedSeveritiesForAI[finding.Severity] && !hasAIRecommendation

	return needsAI, nil
}

// buildFindingDocument converts SecurityFinding to BSON, excluding nil fields
func (s *Service) buildFindingDocument(finding shared.SecurityFinding) (bson.M, error) {
	doc := bson.M{
		"_id":            uuid.New().String(),
		"org_id":         finding.OrgID,
		"discovery_id":   finding.DiscoveryID,
		"finding_type":   finding.FindingType,
		"severity":       finding.Severity,
		"source":         finding.Source,
		"title":          finding.Title,
		"description":    finding.Description,
		"status":         finding.Status,
		"first_detected": finding.Timestamp,
		"last_detected":  finding.Timestamp,
	}

	// Add metadata if present
	if len(finding.Metadata) > 0 {
		doc["metadata"] = finding.Metadata
	}

	return doc, nil
}

// EnsureIndexes creates necessary indexes for the findings collection
func EnsureIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	collection := db.Collection(shared.CollectionFindings)

	indexes := []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "discovery_id", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "severity", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "status", Value: 1},
			},
		},
		{
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "finding_type", Value: 1},
			},
		},
		{
			// Unique index for deduplication
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "discovery_id", Value: 1},
				{Key: "finding_type", Value: 1},
				{Key: "title", Value: 1},
			},
			Options: options.Index().SetUnique(true),
		},
		{
			// Index for scan_ids array queries (used by scan stats computation)
			Keys: bson.D{
				{Key: "org_id", Value: 1},
				{Key: "scan_ids", Value: 1},
			},
			Options: options.Index().
				SetName("idx_org_scan_ids").
				SetPartialFilterExpression(bson.D{
					{Key: "scan_ids", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create findings indexes: %w", err)
	}

	logger.Info("Findings collection indexes created successfully")
	return nil
}

// publishAIEnrichmentJob publishes an AI enrichment job to the queue
func (s *Service) publishAIEnrichmentJob(ctx context.Context, finding shared.SecurityFinding) error {
	job := shared.AIEnrichmentJob{
		TraceID:     finding.TraceID,
		OrgID:       finding.OrgID,
		DiscoveryID: finding.DiscoveryID,
		FindingType: finding.FindingType,
		Title:       finding.Title,
		Severity:    finding.Severity,
		Source:     finding.Source,
		Description: finding.Description,
		Metadata:    finding.Metadata,
		Created:     time.Now(),
	}

	// Inject trace context for distributed tracing
	job.TraceContext = telemetry.InjectTraceContext(ctx)

	// Publish to AI enrichment queue (no MAXLEN - queue should not be trimmed)
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamAIEnrichmentQueue, job, 0); err != nil {
		return fmt.Errorf("failed to publish AI enrichment job: %w", err)
	}

	s.logger.Info("Published AI enrichment job",
		zap.String("org_id", finding.OrgID),
		zap.String("finding_type", finding.FindingType),
		zap.String("severity", finding.Severity),
	)

	return nil
}
