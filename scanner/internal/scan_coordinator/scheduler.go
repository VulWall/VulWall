package scan_coordinator

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Scheduler runs the scan coordinator on a schedule
type Scheduler struct {
	service *Service
	db      *mongo.Database
	logger  *zap.Logger
	tracer  trace.Tracer
}

// NewScheduler creates a new scheduler instance
func NewScheduler(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		service: NewService(redisClient, db, logger),
		db:      db,
		logger:  logger,
		tracer:  otel.Tracer("scan-coordinator"),
	}
}

// Start begins the scheduler loop
func (sc *Scheduler) Start(ctx context.Context) error {
	sc.logger.Info("Scan coordinator scheduler started",
		zap.Duration("interval", SchedulerInterval),
	)

	// Run immediately on startup
	if err := sc.runCoordinationCycle(ctx); err != nil {
		sc.logger.Error("Error running coordination cycle", zap.Error(err))
	}

	// Then run on schedule
	ticker := time.NewTicker(SchedulerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			sc.logger.Info("Scheduler stopped")
			return ctx.Err()
		case <-ticker.C:
			if err := sc.runCoordinationCycle(ctx); err != nil {
				sc.logger.Error("Error running coordination cycle", zap.Error(err))
			}
		}
	}
}

// runCoordinationCycle runs a single coordination cycle
func (sc *Scheduler) runCoordinationCycle(ctx context.Context) error {
	ctx, span := sc.tracer.Start(ctx, "coordination_cycle")
	defer span.End()

	sc.logger.Info("Starting scan coordination cycle")

	// Get all organizations with active subscriptions
	orgs, err := sc.getActiveOrganizations(ctx)
	if err != nil {
		span.RecordError(err)
		return err
	}

	span.SetAttributes(attribute.Int("organization.count", len(orgs)))

	sc.logger.Info("Processing organizations",
		zap.Int("organization_count", len(orgs)),
	)

	// Process each organization
	successCount := 0
	errorCount := 0

	for _, org := range orgs {
		orgCtx, orgSpan := sc.tracer.Start(ctx, "process_organization",
			trace.WithAttributes(
				attribute.String("org.id", org.ID),
				attribute.String("org.name", org.CompanyName),
			),
		)

		if err := sc.service.ProcessOrganization(orgCtx, org); err != nil {
			sc.logger.Error("Failed to process organization",
				zap.String("org_id", org.ID),
				zap.String("company_name", org.CompanyName),
				zap.Error(err),
			)
			orgSpan.RecordError(err)
			errorCount++
		} else {
			successCount++
		}

		orgSpan.End()
	}

	span.SetAttributes(
		attribute.Int("organizations.successful", successCount),
		attribute.Int("organizations.errors", errorCount),
	)

	sc.logger.Info("Scan coordination cycle completed",
		zap.Int("total_organizations", len(orgs)),
		zap.Int("successful", successCount),
		zap.Int("errors", errorCount),
	)

	return nil
}

// getActiveOrganizations retrieves all organizations that should be scanned
func (sc *Scheduler) getActiveOrganizations(ctx context.Context) ([]shared.Organization, error) {
	coll := sc.db.Collection(shared.CollectionOrganizations)

	// Query for organizations with scan_interval_days > 0
	filter := bson.M{
		"subscription_settings.scan_interval_days": bson.M{
			"$gt": 0,
		},
	}

	cursor, err := coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var orgs []shared.Organization
	if err := cursor.All(ctx, &orgs); err != nil {
		return nil, err
	}

	return orgs, nil
}
