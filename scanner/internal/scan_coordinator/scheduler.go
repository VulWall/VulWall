package scan_coordinator

import (
	"context"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
	"github.com/robfig/cron/v3"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Scheduler runs the scan coordinator using cron-based scheduling per organization
type Scheduler struct {
	service     *Service
	db          *mongo.Database
	logger      *zap.Logger
	tracer      trace.Tracer
	cron        *cron.Cron
	entryIDs    map[string]cron.EntryID // org_id -> cron entry ID
	entryIDsMux sync.Mutex
}

// NewScheduler creates a new scheduler instance
func NewScheduler(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		service:  NewService(redisClient, db, logger),
		db:       db,
		logger:   logger,
		tracer:   otel.Tracer("scan-coordinator"),
		cron:     cron.New(cron.WithSeconds()), // Support 6-field cron expressions (seconds, minutes, hours, day, month, weekday)
		entryIDs: make(map[string]cron.EntryID),
	}
}

// Start begins the scheduler by loading organizations and scheduling their scans
func (sc *Scheduler) Start(ctx context.Context) error {
	sc.logger.Info("Scan coordinator scheduler starting with cron-based scheduling")

	// Load all organizations and schedule their scans
	if err := sc.loadAndScheduleOrganizations(ctx); err != nil {
		return fmt.Errorf("failed to load and schedule organizations: %w", err)
	}

	// Schedule periodic refresh to pick up subscription changes
	if _, err := sc.cron.AddFunc(RefreshCron, func() {
		sc.refreshOrganizations()
	}); err != nil {
		return fmt.Errorf("failed to schedule organization refresh: %w", err)
	}

	// Start the cron scheduler
	sc.cron.Start()
	sc.logger.Info("Cron scheduler started",
		zap.Int("scheduled_orgs", len(sc.entryIDs)),
	)

	// Wait for context cancellation
	<-ctx.Done()
	sc.logger.Info("Shutting down cron scheduler")

	// Stop cron and wait for running jobs to complete
	stopCtx := sc.cron.Stop()
	<-stopCtx.Done()

	sc.logger.Info("Cron scheduler stopped")
	return ctx.Err()
}

// loadAndScheduleOrganizations loads all organizations with scan_cron and schedules them
func (sc *Scheduler) loadAndScheduleOrganizations(ctx context.Context) error {
	ctx, span := sc.tracer.Start(ctx, "load_and_schedule_organizations")
	defer span.End()

	orgs, err := sc.getActiveOrganizations(ctx)
	if err != nil {
		span.RecordError(err)
		return err
	}

	span.SetAttributes(attribute.Int("organization.count", len(orgs)))

	sc.logger.Info("Loading organizations for scheduling",
		zap.Int("organization_count", len(orgs)),
	)

	successCount := 0
	errorCount := 0

	for _, org := range orgs {
		if err := sc.scheduleOrganization(ctx, org); err != nil {
			sc.logger.Error("Failed to schedule organization",
				zap.String("org_id", org.ID),
				zap.String("company_name", org.CompanyName),
				zap.String("scan_cron", org.SubscriptionSettings.ScanCron),
				zap.Error(err),
			)
			errorCount++
		} else {
			successCount++
		}
	}

	span.SetAttributes(
		attribute.Int("organizations.scheduled", successCount),
		attribute.Int("organizations.errors", errorCount),
	)

	sc.logger.Info("Organization scheduling completed",
		zap.Int("total_organizations", len(orgs)),
		zap.Int("scheduled", successCount),
		zap.Int("errors", errorCount),
	)

	return nil
}

// scheduleOrganization adds a cron job for a single organization
func (sc *Scheduler) scheduleOrganization(ctx context.Context, org shared.Organization) error {
	cronExpr := org.SubscriptionSettings.ScanCron
	if cronExpr == "" {
		return fmt.Errorf("empty scan_cron for organization %s", org.ID)
	}

	// Create a closure that captures the organization
	// We need to copy org to avoid closure issues
	orgCopy := org
	entryID, err := sc.cron.AddFunc(cronExpr, func() {
		sc.triggerScan(orgCopy)
	})

	if err != nil {
		return fmt.Errorf("invalid cron expression '%s': %w", cronExpr, err)
	}

	// Store the entry ID for potential future removal
	sc.entryIDsMux.Lock()
	sc.entryIDs[org.ID] = entryID
	sc.entryIDsMux.Unlock()

	sc.logger.Info("Scheduled organization scan",
		zap.String("org_id", org.ID),
		zap.String("company_name", org.CompanyName),
		zap.String("scan_cron", cronExpr),
	)

	return nil
}

// triggerScan triggers a scan for an organization
func (sc *Scheduler) triggerScan(org shared.Organization) {
	ctx, span := sc.tracer.Start(context.Background(), "cron_triggered_scan",
		trace.WithAttributes(
			attribute.String("org.id", org.ID),
			attribute.String("org.name", org.CompanyName),
			attribute.String("org.scan_cron", org.SubscriptionSettings.ScanCron),
		),
	)
	defer span.End()

	sc.logger.Info("Cron triggered scan for organization",
		zap.String("org_id", org.ID),
		zap.String("company_name", org.CompanyName),
	)

	if err := sc.service.ProcessOrganization(ctx, org); err != nil {
		sc.logger.Error("Failed to process organization scan",
			zap.String("org_id", org.ID),
			zap.String("company_name", org.CompanyName),
			zap.Error(err),
		)
		span.RecordError(err)
	} else {
		sc.logger.Info("Scan triggered successfully",
			zap.String("org_id", org.ID),
			zap.String("company_name", org.CompanyName),
		)
	}
}

// refreshOrganizations clears all scheduled org scans and reloads from MongoDB
func (sc *Scheduler) refreshOrganizations() {
	ctx, span := sc.tracer.Start(context.Background(), "refresh_organizations")
	defer span.End()

	sc.logger.Info("Refreshing organization schedules")

	// Remove all existing org scan entries
	sc.entryIDsMux.Lock()
	for orgID, entryID := range sc.entryIDs {
		sc.cron.Remove(entryID)
		sc.logger.Debug("Removed cron entry for organization", zap.String("org_id", orgID))
	}
	sc.entryIDs = make(map[string]cron.EntryID)
	sc.entryIDsMux.Unlock()

	// Reload and reschedule all organizations
	if err := sc.loadAndScheduleOrganizations(ctx); err != nil {
		sc.logger.Error("Failed to refresh organization schedules", zap.Error(err))
		span.RecordError(err)
		return
	}

	sc.logger.Info("Organization schedules refreshed",
		zap.Int("scheduled_orgs", len(sc.entryIDs)),
	)
}

// getActiveOrganizations retrieves all organizations that have a valid scan_cron
func (sc *Scheduler) getActiveOrganizations(ctx context.Context) ([]shared.Organization, error) {
	coll := sc.db.Collection(shared.CollectionOrganizations)

	// Query for organizations with non-empty scan_cron
	filter := bson.M{
		"subscription_settings.scan_cron": bson.M{
			"$exists": true,
			"$ne":     "",
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
