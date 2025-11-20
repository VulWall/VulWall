package findings_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service handles persistence of security findings to MongoDB
type Service struct {
	db     *mongo.Database
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new findings ingestion service
func NewService(db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
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
	if finding.Scanner == "" {
		s.logger.Warn("Skipping finding without source field")
		return nil
	}

	if finding.OrgID == "" {
		s.logger.Warn("Skipping finding without org_id")
		return nil
	}

	s.logger.Info("Processing security finding",
		zap.String("org_id", finding.OrgID),
		zap.String("source", finding.Scanner),
		zap.String("finding_type", finding.FindingType),
		zap.String("severity", finding.Severity),
		zap.String("title", finding.Title),
	)

	// Upsert the finding (deduplicate by org_id + discovery_id + finding_type + title)
	if err := s.upsertFinding(ctx, finding); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to upsert finding: %w", err)
	}

	return nil
}

// upsertFinding creates or updates a finding in the findings collection
func (s *Service) upsertFinding(ctx context.Context, finding shared.SecurityFinding) error {
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
			"_id":             uuid.New().String(),
			"org_id":          finding.OrgID,
			"discovery_id":    finding.DiscoveryID,
			"finding_type":    finding.FindingType,
			"severity":        finding.Severity,
			"source":          finding.Scanner,
			"title":           finding.Title,
			"description":     finding.Description,
			"metadata":        finding.Metadata,
			"status":          finding.Status,
			"first_detected":  now,
			"last_detected":   now,
		}

		// Add scan_ids array if present
		if len(scanIDs) > 0 {
			findingDoc["scan_ids"] = scanIDs
		}

		_, err := collection.InsertOne(ctx, findingDoc)
		if err != nil {
			return fmt.Errorf("failed to insert finding: %w", err)
		}

		s.logger.Info("Created new finding",
			zap.String("finding_id", findingDoc["_id"].(string)),
			zap.String("org_id", finding.OrgID),
			zap.String("finding_type", finding.FindingType),
		)

		return nil
	} else if err != nil {
		return fmt.Errorf("failed to query existing finding: %w", err)
	}

	// Finding exists, update last_detected and metadata
	findingID := existingFinding["_id"].(string)

	update := bson.M{
		"$set": bson.M{
			"last_detected": now,
			"metadata":      finding.Metadata, // Update with latest metadata
			"severity":      finding.Severity,  // Update severity in case it changed
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
		return fmt.Errorf("failed to update finding: %w", err)
	}

	s.logger.Info("Updated existing finding",
		zap.String("finding_id", findingID),
		zap.String("org_id", finding.OrgID),
		zap.String("finding_type", finding.FindingType),
	)

	return nil
}

// buildFindingDocument converts SecurityFinding to BSON, excluding nil fields
func (s *Service) buildFindingDocument(finding shared.SecurityFinding) (bson.M, error) {
	doc := bson.M{
		"_id":            uuid.New().String(),
		"org_id":         finding.OrgID,
		"discovery_id":   finding.DiscoveryID,
		"finding_type":   finding.FindingType,
		"severity":       finding.Severity,
		"source":         finding.Scanner,
		"title":          finding.Title,
		"description":    finding.Description,
		"status":         finding.Status,
		"first_detected": finding.Timestamp,
		"last_detected":  finding.Timestamp,
	}

	// Add metadata if present
	if finding.Metadata != nil && len(finding.Metadata) > 0 {
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
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create findings indexes: %w", err)
	}

	logger.Info("Findings collection indexes created successfully")
	return nil
}
