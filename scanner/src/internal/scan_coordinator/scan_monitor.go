package scan_coordinator

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ScanMonitor monitors scan completion and marks scans as done
type ScanMonitor struct {
	redis   *redis.Client
	db      *mongo.Database
	logger  *zap.Logger
	webhook *WebhookNotifier
	tracer  trace.Tracer
}

// NewScanMonitor creates a new scan monitor
func NewScanMonitor(redisClient *redis.Client, db *mongo.Database, webhook *WebhookNotifier, logger *zap.Logger) *ScanMonitor {
	return &ScanMonitor{
		redis:   redisClient,
		db:      db,
		logger:  logger,
		webhook: webhook,
		tracer:  otel.Tracer("scan-monitor"),
	}
}

// Start begins monitoring scans every ScanMonitorInterval (5 minutes)
func (m *ScanMonitor) Start(ctx context.Context) {
	ticker := time.NewTicker(ScanMonitorInterval)
	defer ticker.Stop()

	m.logger.Info("Scan monitor started", zap.Duration("interval", ScanMonitorInterval))

	// Run immediately on start
	if err := m.checkAndMarkComplete(ctx); err != nil {
		m.logger.Error("Initial scan monitoring failed", zap.Error(err))
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Scan monitor stopped")
			return
		case <-ticker.C:
			if err := m.checkAndMarkComplete(ctx); err != nil {
				m.logger.Error("Scan monitoring failed", zap.Error(err))
			}
		}
	}
}

// checkAndMarkComplete checks all active scans and marks them as done if complete
func (m *ScanMonitor) checkAndMarkComplete(ctx context.Context) error {
	ctx, span := m.tracer.Start(ctx, "check_scan_completion")
	defer span.End()

	// Find scans with status="pending" or "running"
	filter := bson.M{
		"status": bson.M{"$in": []string{shared.StatusPending, shared.StatusRunning}},
	}

	cursor, err := m.db.Collection(shared.CollectionScans).Find(ctx, filter)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	defer cursor.Close(ctx)

	var scans []shared.Scan
	if err := cursor.All(ctx, &scans); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetAttributes(attribute.Int("active_scans.count", len(scans)))

	if len(scans) > 0 {
		m.logger.Info("Monitoring scans", zap.Int("active_scans", len(scans)))
	}

	now := time.Now()
	for _, scan := range scans {
		scanAge := now.Sub(scan.CreatedAt)

		// The quiescence barrier is the only completion path that needs a (relatively
		// expensive) Redis round-trip. Compute it lazily — only when the cheap age /
		// activity guards could actually let it complete the scan — so the safety and
		// idle-timeout paths never pay for it.
		quiescent := false
		if quiescenceGuardsMet(scanAge, scan.LastActivityAt, now) {
			q, err := m.pipelineQuiescent(ctx)
			if err != nil {
				m.logger.Warn("Pipeline quiescence check failed; deferring to idle/safety timeout",
					zap.String("scan_id", scan.ID),
					zap.Error(err),
				)
			} else {
				quiescent = q
			}
		}

		complete, reason, timedOut := decideCompletion(scanAge, scan.LastActivityAt, quiescent, now)
		if !complete {
			continue
		}

		logFields := []zap.Field{
			zap.String("scan_id", scan.ID),
			zap.String("completion_reason", reason),
			zap.Duration("duration", scanAge),
		}
		if scan.LastActivityAt != nil {
			logFields = append(logFields, zap.Duration("idle_for", now.Sub(*scan.LastActivityAt)))
		}
		if timedOut {
			m.logger.Warn("Scan safety timeout reached, marking as done", logFields...)
		} else {
			m.logger.Info("Scan complete, marking as done", logFields...)
		}
		span.AddEvent("scan_completed",
			trace.WithAttributes(
				attribute.String("scan.id", scan.ID),
				attribute.String("org.id", scan.OrgID),
				attribute.String("completion_reason", reason),
				attribute.String("scan.duration", scanAge.String()),
			),
		)
		m.markDone(ctx, scan.ID, timedOut)
	}

	span.SetStatus(codes.Ok, "")

	return nil
}

// decideCompletion is the pure completion decision for a single scan, factored out so the
// full truth table can be unit-tested without Redis or MongoDB. Paths, in precedence order:
//
//  1. safety_timeout   — scanAge > ScanSafetyTimeout (3h). Force-complete; timedOut=true so
//     finding resolution is skipped (ingestion may still be incomplete).
//  2. pipeline_quiescent — the scan has run past ScanMinRuntime, ingestion has produced work
//     and been quiet for ScanSettleGrace, AND every finding-producing stream/group has drained
//     (no pending AND no undelivered entries). This replaces the old XPending-only fast path,
//     which was blind to unread trigger messages and marked scans done ~30s in.
//  3. idle_timeout     — a backstop for a stuck or never-created group where quiescence can
//     never be satisfied: no ingestion activity for ScanIdleTimeout after ScanMinRuntime.
//
// A scan that never produced any activity (LastActivityAt == nil) is intentionally closed only
// by the safety timeout — we never want to complete a scan that has shown no sign of work.
func decideCompletion(scanAge time.Duration, lastActivityAt *time.Time, quiescent bool, now time.Time) (complete bool, reason string, timedOut bool) {
	if scanAge > ScanSafetyTimeout {
		return true, "safety_timeout", true
	}

	if quiescent && quiescenceGuardsMet(scanAge, lastActivityAt, now) {
		return true, "pipeline_quiescent", false
	}

	if scanAge > ScanMinRuntime && lastActivityAt != nil && now.Sub(*lastActivityAt) > ScanIdleTimeout {
		return true, "idle_timeout", false
	}

	return false, "", false
}

// quiescenceGuardsMet reports whether a scan is old enough and has been quiet long enough that
// a "pipeline drained" reading can be trusted to mean "done" rather than "hasn't started yet."
// ScanSettleGrace is larger than the ingestion activity-write throttle so a scan that is merely
// between throttled activity writes is not mistaken for settled.
func quiescenceGuardsMet(scanAge time.Duration, lastActivityAt *time.Time, now time.Time) bool {
	return scanAge > ScanMinRuntime &&
		lastActivityAt != nil &&
		now.Sub(*lastActivityAt) > ScanSettleGrace
}

// pipelineQuiescent reports whether every group in scanPipelineGroups() has fully drained its
// stream: nothing pending (read-but-unacked) AND nothing undelivered (last-delivered id == the
// stream's last-generated id).
//
// The undelivered check is the fix. The old XPending-only oracle saw only read-but-unacked
// messages, so triggers sitting unread while a single-threaded scanner (nuclei) worked its
// backlog were invisible — which marked scans "done" ~30s in. The check is stream-wide, not
// scan-scoped, so a concurrent scan can only delay completion, never cause a false one.
func (m *ScanMonitor) pipelineQuiescent(ctx context.Context) (bool, error) {
	groupsByStream := make(map[string][]string)
	for _, sg := range scanPipelineGroups() {
		groupsByStream[sg.Stream] = append(groupsByStream[sg.Stream], sg.Group)
	}

	for stream, requiredGroups := range groupsByStream {
		lastGenerated, err := m.streamLastGeneratedID(ctx, stream)
		if err != nil {
			return false, err
		}

		present, err := m.streamGroups(ctx, stream)
		if err != nil {
			return false, err
		}

		for _, name := range requiredGroups {
			group, ok := present[name]
			if !ok {
				// The group has not been created yet (scanner not started). If the stream
				// already has entries, there may be undelivered work for it → not quiescent.
				// If the stream is empty/absent, there is nothing to process → fine.
				if !isEmptyStreamID(lastGenerated) {
					return false, nil
				}
				continue
			}

			if !groupQuiescent(group.Pending, group.LastDeliveredID, lastGenerated) {
				return false, nil
			}
		}
	}

	return true, nil
}

// groupQuiescent reports whether a single consumer group has drained a stream: nothing pending
// (read-but-unacked) and nothing undelivered (its last-delivered id equals the stream's
// last-generated id). Equality — not ordering — is used deliberately: Redis stream IDs are not
// zero-padded, so lexicographic comparison is unsafe.
func groupQuiescent(pending int64, lastDeliveredID, lastGeneratedID string) bool {
	return pending == 0 && lastDeliveredID == lastGeneratedID
}

// streamLastGeneratedID returns the stream's last-generated entry id, or the empty-stream id
// ("0-0") if the stream does not exist yet.
func (m *ScanMonitor) streamLastGeneratedID(ctx context.Context, stream string) (string, error) {
	info, err := m.redis.XInfoStream(ctx, stream).Result()
	if err != nil {
		if isNoSuchKeyErr(err) {
			return "0-0", nil
		}
		return "", err
	}
	return info.LastGeneratedID, nil
}

// streamGroups returns the consumer groups on a stream keyed by name. A missing stream yields an
// empty map (no groups), not an error.
func (m *ScanMonitor) streamGroups(ctx context.Context, stream string) (map[string]redis.XInfoGroup, error) {
	groups, err := m.redis.XInfoGroups(ctx, stream).Result()
	if err != nil {
		if isNoSuchKeyErr(err) {
			return map[string]redis.XInfoGroup{}, nil
		}
		return nil, err
	}
	byName := make(map[string]redis.XInfoGroup, len(groups))
	for _, g := range groups {
		byName[g.Name] = g
	}
	return byName, nil
}

// isEmptyStreamID reports whether a stream id represents an empty/absent stream.
func isEmptyStreamID(id string) bool {
	return id == "" || id == "0-0"
}

// isNoSuchKeyErr reports whether a Redis error is the "no such key" error returned by XINFO
// commands against a stream that does not exist. Mirrors the check in stream_cleanup.go.
func isNoSuchKeyErr(err error) bool {
	return err != nil && err.Error() == "ERR no such key"
}

// markDone marks a scan as done, resolves disappeared findings, and notifies the Dashboard webhook.
// When timedOut is true, finding resolution is skipped because ingestion may be incomplete.
func (m *ScanMonitor) markDone(ctx context.Context, scanID string, timedOut bool) error {
	// Compute scan statistics before marking as done
	stats, resolvedFindingIDs, err := m.computeStats(ctx, scanID)
	if err != nil {
		m.logger.Error("Failed to compute scan statistics",
			zap.String("scan_id", scanID),
			zap.Error(err),
		)
		// Continue with marking scan as done even if stats computation fails
		stats = &shared.ScanStats{} // Use empty stats as fallback
		resolvedFindingIDs = nil
	}

	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":                     shared.StatusDone,
			"completed_at":               now,
			"updated_at":                 now,
			"stats.total_discoveries":    stats.TotalDiscoveries,
			"stats.new_discoveries":      stats.NewDiscoveries,
			"stats.resolved_discoveries": stats.ResolvedDiscoveries,
			"stats.total_findings":       stats.TotalFindings,
			"stats.new_findings":         stats.NewFindings,
			"stats.resolved_findings":    stats.ResolvedFindings,
		},
	}

	result, err := m.db.Collection(shared.CollectionScans).UpdateOne(
		ctx,
		bson.M{"_id": scanID},
		update,
	)

	if err != nil {
		m.logger.Error("Failed to mark scan as done",
			zap.String("scan_id", scanID),
			zap.Error(err),
		)
		return err
	}

	if result.ModifiedCount > 0 {
		m.logger.Info("Scan marked as done",
			zap.String("scan_id", scanID),
			zap.Time("completed_at", now),
		)

		// Mark disappeared findings as resolved. Skip on timeout (ingestion may be
		// incomplete) and skip when the scan discovered nothing — a scan with zero
		// discoveries has produced no evidence and must never mass-resolve the prior
		// scan's real findings (belt-and-suspenders against a premature completion).
		switch {
		case timedOut:
			m.logger.Warn("Skipping finding resolution for timed-out scan",
				zap.String("scan_id", scanID),
				zap.Int("would_resolve", len(resolvedFindingIDs)),
			)
		case stats.TotalDiscoveries == 0:
			m.logger.Warn("Skipping finding resolution for scan with zero discoveries",
				zap.String("scan_id", scanID),
				zap.Int("would_resolve", len(resolvedFindingIDs)),
			)
		default:
			m.resolveDisappearedFindings(ctx, scanID, resolvedFindingIDs)
		}

		// Notify Dashboard asynchronously (non-blocking, best-effort)
		go m.webhook.NotifyScanComplete(scanID)
	}

	return nil
}

// resolveDisappearedFindings bulk-updates findings that were present in the previous scan
// but absent in the current scan, marking them as resolved. This is best-effort: errors
// are logged but do not fail the scan completion.
func (m *ScanMonitor) resolveDisappearedFindings(ctx context.Context, scanID string, resolvedFindingIDs []string) {
	if len(resolvedFindingIDs) == 0 {
		return
	}

	ctx, span := m.tracer.Start(ctx, "resolve_disappeared_findings",
		trace.WithAttributes(
			attribute.String("scan.id", scanID),
			attribute.Int("findings.resolved_count", len(resolvedFindingIDs)),
		),
	)
	defer span.End()

	now := time.Now()
	result, err := m.db.Collection(shared.CollectionFindings).UpdateMany(ctx,
		bson.M{"_id": bson.M{"$in": resolvedFindingIDs}},
		bson.M{"$set": bson.M{
			"status":              shared.FindingStatusResolved,
			"resolved_at":         now,
			"resolved_by_scan_id": scanID,
		}},
	)

	if err != nil {
		m.logger.Error("Failed to mark findings as resolved",
			zap.String("scan_id", scanID),
			zap.Int("count", len(resolvedFindingIDs)),
			zap.Error(err),
		)
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to resolve findings")
		return
	}

	m.logger.Info("Marked findings as resolved",
		zap.String("scan_id", scanID),
		zap.Int("expected", len(resolvedFindingIDs)),
		zap.Int64("updated", result.ModifiedCount),
	)

	span.AddEvent("findings_resolved",
		trace.WithAttributes(
			attribute.String("scan.id", scanID),
			attribute.Int("findings.expected", len(resolvedFindingIDs)),
			attribute.Int64("findings.updated", result.ModifiedCount),
		),
	)
	span.SetStatus(codes.Ok, "")
}
