package scan_coordinator

import (
	"context"
	"fmt"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// StartQueuedScans polls the scans collection for queued scans and starts
// them. It blocks until ctx is cancelled.
//
// The web UI inserts {_id, org_id, status: "queued", type: "requested",
// triggered_by, created_at}; TriggerScan inserts the same shape with type
// "scheduled" when the cron fires during a running scan.
// The poller claims the document in place (queued -> running) and publishes the
// discovery jobs under that same _id, so the UI can follow the scan it created.
//
// A queued scan for an organization that already has a pending or running scan
// stays queued and starts on a later poll, after the running scan finishes.
func (s *Service) StartQueuedScans(ctx context.Context) {
	ticker := time.NewTicker(QueuedScanPollInterval)
	defer ticker.Stop()

	s.logger.Info("Queued-scan poller started", zap.Duration("interval", QueuedScanPollInterval))

	for {
		s.startQueuedScans(ctx)
		select {
		case <-ctx.Done():
			s.logger.Info("Queued-scan poller stopped")
			return
		case <-ticker.C:
		}
	}
}

// startQueuedScans runs one poll: it tries to start the oldest queued scan of
// each organization.
func (s *Service) startQueuedScans(ctx context.Context) {
	scans, err := s.store.queuedScans(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Error("Failed to list queued scans", zap.Error(err))
		}
		return
	}

	seenOrgs := make(map[string]bool, len(scans))
	for _, scan := range scans {
		if seenOrgs[scan.OrgID] {
			continue // only the oldest queued scan per org can start in one poll
		}
		seenOrgs[scan.OrgID] = true
		s.startQueuedScan(ctx, scan)
	}
}

// startQueuedScan claims one queued scan and publishes its discovery jobs.
// Transient errors leave the scan queued so the next poll retries it.
func (s *Service) startQueuedScan(ctx context.Context, queued shared.Scan) {
	ctx, span := s.tracer.Start(ctx, "start_queued_scan",
		trace.WithAttributes(
			attribute.String("scan.id", queued.ID),
			attribute.String("org.id", queued.OrgID),
		),
	)
	defer span.End()

	log := s.logger.With(zap.String("scan_id", queued.ID), zap.String("org_id", queued.OrgID))

	s.startMu.Lock()
	defer s.startMu.Unlock()

	exists, err := s.store.orgExists(ctx, queued.OrgID)
	if err != nil {
		log.Error("Failed to verify organization for queued scan", zap.Error(err))
		return
	}
	if !exists {
		s.finishQueued(ctx, queued.ID, shared.StatusFailed, ErrOrgNotFound)
		return
	}

	busy, err := s.store.hasScanIn(ctx, queued.OrgID, startedStatuses)
	if err != nil {
		log.Error("Failed to check running scans for queued scan", zap.Error(err))
		return
	}
	if busy {
		log.Debug("Queued scan waits: organization has a running scan")
		return
	}

	// Claim first, then read the assets: while the scan is queued, the web app promises that
	// it includes every asset added before it starts, so an asset added up to the claim must
	// be in it. After the claim the web app sees a running scan and queues a follow-up.
	// A scheduled scan queued behind a running one keeps its type, so the web
	// app labels it Scheduled; anything else is a requested scan.
	scanType := shared.ScanTypeRequested
	if queued.Type == shared.ScanTypeScheduled {
		scanType = shared.ScanTypeScheduled
	}
	now := time.Now()
	claimed, err := s.store.claimQueuedScan(ctx, queued.ID, bson.M{
		"status":     shared.StatusRunning,
		"type":       scanType,
		"started_at": now,
		"updated_at": now,
	})
	if err != nil {
		log.Error("Failed to claim queued scan", zap.Error(err))
		return
	}
	if !claimed {
		log.Info("Queued scan changed before it was claimed; skipping")
		return
	}

	// The scan is ours now: a failure from here on closes it, or it would stay running
	// and block the organization's next scan until the safety timeout.
	assets, err := s.store.orgAssets(ctx, queued.OrgID)
	if err != nil {
		s.markFailed(ctx, queued.ID, fmt.Errorf("load assets: %w", err))
		span.RecordError(err)
		return
	}
	targets := s.targetsFor(queued.OrgID, assets)

	set := bson.M{
		"targeted_assets":    targets,
		"stats.total_assets": len(targets),
		"updated_at":         time.Now(),
	}
	// Nothing to scan: complete at once instead of leaving a running scan
	// that the monitor would only close at the safety timeout. It saw nothing,
	// so it reconciles no findings and is no baseline for the next scan.
	if len(targets) == 0 {
		set["status"] = shared.StatusDone
		set["completed_at"] = set["updated_at"]
		set["findings_reconciled"] = false
	}
	if err := s.store.setScanFields(ctx, queued.ID, set); err != nil {
		s.markFailed(ctx, queued.ID, fmt.Errorf("record targeted assets: %w", err))
		span.RecordError(err)
		return
	}

	if len(targets) == 0 {
		log.Warn("Queued scan has no enabled assets; marked done")
		return
	}

	if err := s.publishDiscoveryJobs(ctx, queued.OrgID, queued.ID, assets); err != nil {
		s.markFailed(ctx, queued.ID, err)
		span.RecordError(err)
		return
	}

	log.Info("Started queued scan",
		zap.String("triggered_by", queued.TriggeredBy),
		zap.Int("targeted_assets_count", len(targets)),
	)
}

// finishQueued closes a queued scan that can never start.
func (s *Service) finishQueued(ctx context.Context, scanID, status string, cause error) {
	now := time.Now()
	claimed, err := s.store.claimQueuedScan(ctx, scanID, bson.M{
		"status":       status,
		"completed_at": now,
		"updated_at":   now,
	})
	s.logger.Warn("Queued scan cannot start",
		zap.String("scan_id", scanID),
		zap.String("status", status),
		zap.Bool("updated", claimed),
		zap.NamedError("cause", cause),
		zap.Error(err),
	)
}
