package kb_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Service handles persistence of knowledge base entries to MongoDB
type Service struct {
	db     *mongo.Database
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new KB ingestion service
func NewService(db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
		tracer: otel.Tracer("kb-ingestion"),
	}
}

// ProcessEntry processes a KB generation result and upserts it to the knowledge_base collection
func (s *Service) ProcessEntry(ctx context.Context, result shared.KBGenerationResult) error {
	ctx, span := s.tracer.Start(ctx, "ingest_kb_entry",
		trace.WithAttributes(
			attribute.String("trace.id", result.TraceID),
			attribute.String("finding.type", result.FindingType),
			attribute.String("model", result.Model),
		),
	)
	defer span.End()

	if result.FindingType == "" {
		s.logger.Warn("Skipping KB result without finding_type")
		return nil
	}

	s.logger.Info("Processing KB entry",
		zap.String("finding_type", result.FindingType),
		zap.String("model", result.Model),
	)

	if err := s.upsertKBEntry(ctx, result); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to upsert KB entry: %w", err)
	}

	return nil
}

// upsertKBEntry writes a KB entry to the knowledge_base collection
// Uses $setOnInsert so the first write creates the entry and subsequent writes for the same finding_type are no-ops
func (s *Service) upsertKBEntry(ctx context.Context, result shared.KBGenerationResult) error {
	collection := s.db.Collection(shared.CollectionKnowledgeBase)

	docID := "kb_" + result.FindingType

	filter := bson.M{"_id": docID}

	update := bson.M{
		"$setOnInsert": bson.M{
			"_id":          docID,
			"finding_type": result.FindingType,
			"business":     extractSection(result.Entry, "business"),
			"technical":    extractSection(result.Entry, "technical"),
			"metadata":     extractSection(result.Entry, "metadata"),
			"model":        result.Model,
			"published":    false,
			"created_at":   time.Now(),
			"version":    1,
			"updated_at": nil,
		},
	}

	opts := options.Update().SetUpsert(true)

	updateResult, err := collection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to upsert KB entry: %w", err)
	}

	if updateResult.UpsertedCount > 0 {
		s.logger.Info("Created new KB entry",
			zap.String("finding_type", result.FindingType),
			zap.String("doc_id", docID),
		)
	} else {
		s.logger.Debug("KB entry already exists, skipping",
			zap.String("finding_type", result.FindingType),
		)
	}

	return nil
}

// extractSection safely extracts a section from the entry map
func extractSection(entry map[string]interface{}, key string) interface{} {
	if val, ok := entry[key]; ok {
		return val
	}
	return nil
}

// EnsureIndexes creates necessary indexes for the knowledge_base collection
func EnsureIndexes(ctx context.Context, db *mongo.Database, logger *zap.Logger) error {
	collection := db.Collection(shared.CollectionKnowledgeBase)

	indexes := []mongo.IndexModel{
		{
			// Unique index on finding_type for fast lookups
			Keys:    bson.D{{Key: "finding_type", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create knowledge_base indexes: %w", err)
	}

	logger.Info("Knowledge base collection indexes created successfully")
	return nil
}
