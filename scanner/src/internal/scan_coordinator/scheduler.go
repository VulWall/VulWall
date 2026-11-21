package scan_coordinator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/robfig/cron/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Scheduler runs the scan coordinator using cron-based scheduling per organization
type Scheduler struct {
	service       *Service
	db            *mongo.Database
	logger        *zap.Logger
	tracer        trace.Tracer
	cron          *cron.Cron
	entries       map[string]orgEntry // org_id -> its scheduled scan
	entriesMux    sync.Mutex
	streamCleaner *StreamCleaner
}

// orgEntry is one organization's scheduled scan. entryID is 0 when the cron expression
// was rejected; the organization is then retried only after its cron changes.
type orgEntry struct {
	entryID  cron.EntryID
	cronExpr string
}

// NewScheduler creates a new scheduler instance
func NewScheduler(service *Service, db *mongo.Database, streamCleaner *StreamCleaner, logger *zap.Logger) *Scheduler {
	return &Scheduler{
		service:       service,
		db:            db,
		logger:        logger,
		tracer:        otel.Tracer("scan-coordinator"),
		cron:          cron.New(cron.WithLocation(time.UTC)), // 5-field cron; the web app stores scan_cron in UTC
		entries:       make(map[string]orgEntry),
		streamCleaner: streamCleaner,
	}
}

// Start begins the scheduler by loading organizations and scheduling their scans
func (sc *Scheduler) Start(ctx context.Context) error {
	sc.logger.Info("Scan coordinator scheduler starting with cron-based scheduling")

	if err := sc.refreshOrganizations(ctx); err != nil {
		return fmt.Errorf("failed to load and schedule organizations: %w", err)
	}

	// Reload organizations periodically to pick up schedule changes from the web app
	if _, err := sc.cron.AddFunc(RefreshCron, func() {
		if err := sc.refreshOrganizations(context.Background()); err != nil {
			sc.logger.Error("Failed to refresh organization schedules; keeping the current ones", zap.Error(err))
		}
	}); err != nil {
		return fmt.Errorf("failed to schedule organization refresh: %w", err)
	}

	// Schedule periodic stream cleanup (trims fully-processed messages)
	if _, err := sc.cron.AddFunc(StreamCleanupCron, func() {
		sc.streamCleaner.Run()
	}); err != nil {
		return fmt.Errorf("failed to schedule stream cleanup: %w", err)
	}

	// Start the cron scheduler
	sc.cron.Start()
	sc.logger.Info("Cron scheduler started",
		zap.Int("scheduled_orgs", sc.scheduledCount()),
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

// refreshOrganizations loads all organizations and brings the cron entries in line with
// their schedules. When the load fails, the current entries stay as they are.
func (sc *Scheduler) refreshOrganizations(ctx context.Context) error {
	ctx, span := sc.tracer.Start(ctx, "refresh_organizations")
	defer span.End()

	orgs, err := sc.getOrganizations(ctx)
	if err != nil {
		span.RecordError(err)
		return err
	}
	span.SetAttributes(attribute.Int("organization.count", len(orgs)))
	sc.applySchedules(orgs)
	return nil
}

// applySchedules adds, replaces and removes cron entries so that exactly the organizations
// with an active schedule have one, at their current cron. Unchanged entries are kept, so a
// refresh never delays or repeats a scan that is not affected.
func (sc *Scheduler) applySchedules(orgs []shared.Organization) {
	desired := make(map[string]shared.Organization, len(orgs))
	for _, org := range orgs {
		if org.ScanSettings.Scheduled() {
			desired[org.ID] = org
		}
	}

	sc.entriesMux.Lock()
	defer sc.entriesMux.Unlock()

	for orgID, entry := range sc.entries {
		org, ok := desired[orgID]
		if ok && org.ScanSettings.ScanCron == entry.cronExpr {
			continue
		}
		if entry.entryID != 0 {
			sc.cron.Remove(entry.entryID)
		}
		delete(sc.entries, orgID)
		if !ok {
			sc.logger.Info("Removed organization scan schedule", zap.String("org_id", orgID))
		}
	}

	for orgID, org := range desired {
		if _, ok := sc.entries[orgID]; ok {
			continue
		}
		cronExpr := org.ScanSettings.ScanCron
		entryID, err := sc.cron.AddFunc(cronExpr, func() {
			sc.triggerScan(org)
		})
		if err != nil {
			sc.logger.Error("Invalid scan_cron; organization not scheduled",
				zap.String("org_id", orgID),
				zap.String("scan_cron", cronExpr),
				zap.Error(err),
			)
			entryID = 0
		} else {
			sc.logger.Info("Scheduled organization scan",
				zap.String("org_id", orgID),
				zap.String("company_name", org.CompanyName),
				zap.String("scan_cron", cronExpr),
			)
		}
		sc.entries[orgID] = orgEntry{entryID: entryID, cronExpr: cronExpr}
	}
}

// scheduledCount returns how many organizations have a valid scheduled scan.
func (sc *Scheduler) scheduledCount() int {
	sc.entriesMux.Lock()
	defer sc.entriesMux.Unlock()
	n := 0
	for _, e := range sc.entries {
		if e.entryID != 0 {
			n++
		}
	}
	return n
}

// triggerScan triggers a scan for an organization
func (sc *Scheduler) triggerScan(org shared.Organization) {
	ctx, span := sc.tracer.Start(context.Background(), "cron_triggered_scan",
		trace.WithAttributes(
			attribute.String("org.id", org.ID),
			attribute.String("org.name", org.CompanyName),
			attribute.String("org.scan_cron", org.ScanSettings.ScanCron),
		),
	)
	defer span.End()

	sc.logger.Info("Cron triggered scan for organization",
		zap.String("org_id", org.ID),
		zap.String("company_name", org.CompanyName),
	)

	if scanID, err := sc.service.TriggerScan(ctx, ScanRequest{
		OrgID:       org.ID,
		Type:        shared.ScanTypeScheduled,
		TriggeredBy: "system",
	}); errors.Is(err, ErrScanInProgress) {
		sc.logger.Info("Skipping cron scan: a scan is already queued",
			zap.String("org_id", org.ID),
		)
	} else if errors.Is(err, ErrScanQueued) {
		sc.logger.Info("Cron scan queued: it starts after the running scan",
			zap.String("org_id", org.ID),
			zap.String("scan_id", scanID),
		)
	} else if err != nil {
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

// getOrganizations retrieves every organization; applySchedules decides which get a scan.
// A self-hosted install has one, so there is no filter.
func (sc *Scheduler) getOrganizations(ctx context.Context) ([]shared.Organization, error) {
	cursor, err := sc.db.Collection(shared.CollectionOrganizations).Find(ctx, bson.M{})
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
