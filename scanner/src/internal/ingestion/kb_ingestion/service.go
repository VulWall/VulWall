package kb_ingestion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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

	if injected, marker := containsInjectionPayload(result.Entry); injected {
		s.logger.Error("KB entry rejected: prompt injection detected in generated content",
			zap.String("finding_type", result.FindingType),
			zap.String("marker", marker),
		)
		span.SetAttributes(attribute.Bool("scan.success", false))
		span.SetStatus(codes.Error, "prompt injection detected")
		// Return nil (not error) so the message is acked and not retried — a retry
		// would produce the same poisoned output. The entry is simply dropped.
		return nil
	}

	s.logger.Info("Processing KB entry",
		zap.String("finding_type", result.FindingType),
		zap.String("model", result.Model),
	)

	if err := s.upsertKBEntry(ctx, result); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("scan.success", false))
		return fmt.Errorf("failed to upsert KB entry: %w", err)
	}

	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	return nil
}

// upsertKBEntry writes a KB entry to the knowledge_base collection
func (s *Service) upsertKBEntry(ctx context.Context, result shared.KBGenerationResult) error {
	collection := s.db.Collection(shared.CollectionKnowledgeBase)

	docID := "kb_" + result.FindingType

	filter := bson.M{"_id": docID}

	update := kbUpsertUpdate(result, time.Now())

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
		s.logger.Info("Updated existing KB entry",
			zap.String("finding_type", result.FindingType),
			zap.String("model", result.Model),
		)
	}

	return nil
}

// injectionMarkers are lowercase substrings that reliably indicate a prompt
// injection payload survived Claude's instruction-level guards. The list is
// intentionally narrow — only strings that cannot plausibly appear in a
// legitimate security KB entry.
var injectionMarkers = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"forget previous instructions",
	"disregard previous instructions",
	"you are now",
	"new instructions:",
	"system prompt:",
}

// containsInjectionPayload scans all string values in the generated entry for
// known injection markers. Returns true and the matched marker if found.
// Serialises the entire entry to JSON so nested fields are covered in one pass.
func containsInjectionPayload(entry map[string]interface{}) (bool, string) {
	raw, err := json.Marshal(entry)
	if err != nil {
		return false, ""
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range injectionMarkers {
		if strings.Contains(lower, marker) {
			return true, marker
		}
	}
	return false, ""
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

// kbUpsertUpdate builds the upsert document for a KB entry. New entries are
// inserted as published; re-generation never changes an existing entry's
// published flag.
func kbUpsertUpdate(result shared.KBGenerationResult, now time.Time) bson.M {
	return bson.M{
		"$set": bson.M{
			"finding_type": result.FindingType,
			"business":     extractSection(result.Entry, "business"),
			"technical":    extractSection(result.Entry, "technical"),
			"metadata":     extractSection(result.Entry, "metadata"),
			"model":        result.Model,
			"updated_at":   now,
		},
		"$setOnInsert": bson.M{
			"_id":        "kb_" + result.FindingType,
			"published":  true, // self-hosted: no admin review step, entries are visible immediately
			"created_at": now,
		},
		"$inc": bson.M{
			"version": 1,
		},
	}
}
