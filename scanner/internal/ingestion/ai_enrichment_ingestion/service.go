package ai_enrichment_ingestion

import (
	"context"
	"fmt"

	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service handles persistence of AI enrichments to MongoDB
type Service struct {
	db     *mongo.Database
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new AI enrichment ingestion service
func NewService(db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
		tracer: otel.Tracer("ai-enrichment-ingestion"),
	}
}

// ProcessEnrichment processes an AI enrichment and updates the finding in MongoDB
func (s *Service) ProcessEnrichment(ctx context.Context, enrichment shared.AIEnrichmentFinding) error {
	ctx, span := s.tracer.Start(ctx, "ingest_ai_enrichment",
		trace.WithAttributes(
			attribute.String("org.id", enrichment.OrgID),
			attribute.String("trace.id", enrichment.TraceID),
			attribute.String("discovery.id", enrichment.DiscoveryID),
			attribute.String("finding.type", enrichment.FindingType),
			attribute.String("prompt.used", enrichment.PromptUsed),
			attribute.String("model", enrichment.Model),
		),
	)
	defer span.End()

	// Validate required fields
	if enrichment.OrgID == "" {
		s.logger.Warn("Skipping enrichment without org_id")
		return nil
	}

	if enrichment.DiscoveryID == "" || enrichment.FindingType == "" || enrichment.Title == "" {
		s.logger.Warn("Skipping enrichment with missing composite key fields",
			zap.String("discovery_id", enrichment.DiscoveryID),
			zap.String("finding_type", enrichment.FindingType),
			zap.String("title", enrichment.Title),
		)
		return nil
	}

	s.logger.Info("Processing AI enrichment",
		zap.String("org_id", enrichment.OrgID),
		zap.String("discovery_id", enrichment.DiscoveryID),
		zap.String("finding_type", enrichment.FindingType),
		zap.String("model", enrichment.Model),
	)

	// Update the finding with AI recommendation
	if err := s.updateFinding(ctx, enrichment); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to update finding: %w", err)
	}

	return nil
}

// updateFinding updates a finding document with the AI recommendation
func (s *Service) updateFinding(ctx context.Context, enrichment shared.AIEnrichmentFinding) error {
	collection := s.db.Collection(shared.CollectionFindings)

	// Use composite key to find the finding (matches unique index)
	// Also check that ai_recommendation doesn't already exist (skip if already enriched)
	filter := bson.M{
		"org_id":       enrichment.OrgID,
		"discovery_id": enrichment.DiscoveryID,
		"finding_type": enrichment.FindingType,
		"title":        enrichment.Title,
		"ai_recommendation": bson.M{
			"$exists": false,
		},
	}

	// Update with AI recommendation
	update := bson.M{
		"$set": bson.M{
			"ai_recommendation": bson.M{
				"content":      enrichment.Recommendation,
				"prompt_used":  enrichment.PromptUsed,
				"model":        enrichment.Model,
				"generated_at": enrichment.Timestamp,
			},
		},
	}

	result, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update finding: %w", err)
	}

	if result.MatchedCount == 0 {
		// Could be either: finding not found OR already has AI recommendation
		s.logger.Debug("Finding not updated (not found or already enriched)",
			zap.String("org_id", enrichment.OrgID),
			zap.String("discovery_id", enrichment.DiscoveryID),
			zap.String("finding_type", enrichment.FindingType),
		)
		return nil
	}

	s.logger.Info("AI recommendation added to finding",
		zap.String("org_id", enrichment.OrgID),
		zap.String("finding_type", enrichment.FindingType),
		zap.Int64("matched", result.MatchedCount),
		zap.Int64("modified", result.ModifiedCount),
	)

	return nil
}
