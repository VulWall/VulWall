package audit_ingestion

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

// Service handles persistence of system audit events to MongoDB
type Service struct {
	db     *mongo.Database
	logger *zap.Logger
	tracer trace.Tracer
}

// NewService creates a new audit ingestion service
func NewService(db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
		tracer: otel.Tracer("audit-ingestion"),
	}
}

// ProcessAuditEvent processes a system audit event and persists it to MongoDB
func (s *Service) ProcessAuditEvent(ctx context.Context, event shared.SystemAuditEvent) error {
	ctx, span := s.tracer.Start(ctx, "ingest_audit_event",
		trace.WithAttributes(
			attribute.String("category", event.Category),
			attribute.String("action", event.Action),
			attribute.String("service", event.Service),
			attribute.Bool("success", event.Success),
		),
	)
	defer span.End()

	s.logger.Info("Processing system audit event",
		zap.String("category", event.Category),
		zap.String("action", event.Action),
		zap.String("service", event.Service),
		zap.Bool("success", event.Success),
	)

	collection := s.db.Collection(shared.CollectionAuditLogs)

	// Build document matching existing audit_logs schema
	doc := bson.M{
		"org_id":         nil,                  // System events have no org_id
		"UserId":         "system",             // System user identifier
		"UserName":       event.Service,        // Service name as username
		"Category":       event.Category,       // e.g., "TemplateUpdate"
		"Action":         event.Action,         // e.g., "Nuclei templates updated"
		"AdditionalInfo": event.AdditionalInfo, // Version info, output, etc.
		"IpAddress":      nil,                  // No IP for system events
		"CreatedAt":      event.Timestamp,
	}

	_, err := collection.InsertOne(ctx, doc)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to insert audit log: %w", err)
	}

	s.logger.Info("Persisted system audit event",
		zap.String("category", event.Category),
		zap.String("action", event.Action),
		zap.String("service", event.Service),
	)

	return nil
}
