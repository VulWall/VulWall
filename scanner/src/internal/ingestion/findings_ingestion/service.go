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
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

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
	if err := s.upsertFinding(ctx, finding); err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to upsert finding: %w", err)
	}

	// Check if a KB entry needs to be generated for this finding_type.
	// Only generate for actionable severities (critical, high, medium) — info and low
	// findings are not worth the API cost and are rarely remediated by SME customers.
	// Uses Redis SETNX lock to prevent duplicate API calls for the same finding_type.
	if finding.FindingType != "" && kbEligibleSeverity(finding.Severity) {
		lockKey := "kb_generating:" + finding.FindingType
		locked, err := s.redis.SetNX(ctx, lockKey, "1", 24*time.Hour).Result()
		if err != nil {
			s.logger.Warn("Failed to check KB dedup lock, skipping KB generation",
				zap.String("finding_type", finding.FindingType),
				zap.Error(err),
			)
		} else if locked && !s.kbEntryExists(ctx, finding.FindingType) {
			if err := s.publishKBGenerationJob(ctx, finding); err != nil {
				// Log error but don't fail the ingestion; release lock so it can be retried
				s.logger.Error("Failed to publish KB generation job",
					zap.String("finding_type", finding.FindingType),
					zap.Error(err),
				)
				s.redis.Del(ctx, lockKey)
			}
		}
	}

	return nil
}

// upsertFinding creates or updates a finding in the findings collection
func (s *Service) upsertFinding(ctx context.Context, finding shared.SecurityFinding) error {
	// Use majority write concern to ensure writes are confirmed before ACK
	collection := s.db.Collection(
		shared.CollectionFindings,
		options.Collection().SetWriteConcern(writeconcern.Majority()),
	)

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

// kbEligibleSeverity returns true for severities that warrant KB entry generation.
// Info and low findings are excluded — they are rarely actionable for SME customers
// and not worth the Anthropic API + web search cost.
func kbEligibleSeverity(severity string) bool {
	switch severity {
	case shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium:
		return true
	default:
		return false
	}
}

// kbEntryExists checks if a knowledge base entry already exists for the given finding type
func (s *Service) kbEntryExists(ctx context.Context, findingType string) bool {
	collection := s.db.Collection(shared.CollectionKnowledgeBase)
	docID := "kb_" + findingType

	err := collection.FindOne(ctx, bson.M{"_id": docID}).Err()
	return err == nil
}

// safeMetadataForKB returns a filtered copy of metadata safe for LLM prompts.
// Uses an ALLOWLIST — only explicitly safe keys are included. Everything else
// is dropped because scanner metadata may contain attacker-controlled content
// from scanned targets (HTTP responses, headers, page content, etc.).
//
// When adding a new scanner, only add keys here if they contain structured,
// scanner-generated data — never raw content from scan targets.
func safeMetadataForKB(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	// Only these keys are safe for LLM prompts. They contain structured,
	// scanner-generated data that is not influenced by scanned targets.
	allowKeys := map[string]bool{
		"cve_id":            true, // CVE identifier (e.g., "CVE-2024-1234")
		"cvss_score":        true, // CVSS score from scanner
		"cvss_vector":       true, // CVSS vector string
		"affected_versions": true, // Version range affected
		"technology":        true, // Technology name (e.g., "jQuery", "nginx")
		"template_severity": true, // Nuclei template severity
		"reference":         true, // Reference URLs from template (not from target)
		"classification":    true, // Scanner classification data
		"tags":              true, // Scanner-assigned tags
	}

	safe := make(map[string]interface{})
	for k, v := range metadata {
		if allowKeys[k] {
			safe[k] = v
		}
	}
	if len(safe) == 0 {
		return nil
	}
	return safe
}

// publishKBGenerationJob publishes a KB generation job to the queue
func (s *Service) publishKBGenerationJob(ctx context.Context, finding shared.SecurityFinding) error {
	job := shared.KBGenerationJob{
		FindingType: finding.FindingType,
		Title:       finding.Title,
		Severity:    finding.Severity,
		Source:      finding.Source,
		Description: finding.Description,
		Metadata:    safeMetadataForKB(finding.Metadata),
		TraceID:     finding.TraceID,
		Created:     time.Now(),
	}

	// Inject trace context for distributed tracing
	job.TraceContext = telemetry.InjectTraceContext(ctx)

	// Publish to KB generation queue (no MAXLEN - queue should not be trimmed)
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamKBGenerationQueue, job, 0); err != nil {
		return fmt.Errorf("failed to publish KB generation job: %w", err)
	}

	s.logger.Info("Published KB generation job",
		zap.String("finding_type", finding.FindingType),
		zap.String("severity", finding.Severity),
	)

	return nil
}
