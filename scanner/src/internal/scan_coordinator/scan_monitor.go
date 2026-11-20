package scan_coordinator

import (
	"context"
	"os"
	"slices"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
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
	redis  *redis.Client
	db     *mongo.Database
	logger *zap.Logger
	tracer trace.Tracer
	policy completionPolicy
}

// NewScanMonitor creates a new scan monitor
func NewScanMonitor(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *ScanMonitor {
	policy := loadCompletionPolicy(logger)
	logger.Info("Scan completion policy",
		zap.Duration("min_runtime", policy.minRuntime),
		zap.Duration("idle_timeout", policy.idleTimeout),
		zap.Duration("settle_grace", policy.settleGrace),
		zap.Duration("stuck_threshold", policy.stuckAfter),
		zap.Duration("safety_timeout", policy.safetyTimeout),
	)
	return &ScanMonitor{
		redis:  redisClient,
		db:     db,
		logger: logger,
		tracer: otel.Tracer("scan-monitor"),
		policy: policy,
	}
}

// completionPolicy holds the thresholds of decideCompletion.
type completionPolicy struct {
	minRuntime    time.Duration
	idleTimeout   time.Duration
	settleGrace   time.Duration
	stuckAfter    time.Duration
	safetyTimeout time.Duration
}

func defaultCompletionPolicy() completionPolicy {
	return completionPolicy{
		minRuntime:    ScanMinRuntime,
		idleTimeout:   ScanIdleTimeout,
		settleGrace:   ScanSettleGrace,
		stuckAfter:    ScanStuckThreshold,
		safetyTimeout: ScanSafetyTimeout,
	}
}

// loadCompletionPolicy returns the default policy with SCAN_IDLE_TIMEOUT and SCAN_MIN_RUNTIME
// applied. A value that is not a positive Go duration is logged and ignored.
func loadCompletionPolicy(log *zap.Logger) completionPolicy {
	p := defaultCompletionPolicy()
	for _, o := range []struct {
		env string
		dst *time.Duration
	}{
		{config.EnvScanIdleTimeout, &p.idleTimeout},
		{config.EnvScanMinRuntime, &p.minRuntime},
	} {
		raw := os.Getenv(o.env)
		if raw == "" {
			continue
		}
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			log.Warn("Ignoring invalid duration; using the default",
				zap.String("env", o.env), zap.String("value", raw), zap.Duration("default", *o.dst))
			continue
		}
		*o.dst = d
	}
	return p
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
	p := m.policy
	for _, scan := range scans {
		scanAge := now.Sub(scanStartTime(scan))

		// The Redis reads are computed lazily — only when the cheap age / activity guards
		// could let them matter — so most ticks of a running scan cost no Redis round-trip.
		quiescent := false
		if p.quiescenceGuardsMet(scanAge, scan.LastActivityAt, now) {
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

		inFlight := false
		if !quiescent && p.idleGuardsMet(scanAge, scan.LastActivityAt, now) {
			work, err := freshPendingWork(ctx, redisStreamInfo{m.redis}, scanPipelineGroups(), p.stuckAfter)
			switch {
			case err != nil:
				// Without the reading, keep the scan open: the safety timeout still ends it.
				inFlight = true
				m.logger.Warn("Work-in-flight check failed; not applying the idle timeout",
					zap.String("scan_id", scan.ID), zap.Error(err))
			case work != nil:
				inFlight = true
				m.logger.Info("Idle timeout suppressed: work in flight",
					zap.String("scan_id", scan.ID),
					zap.Duration("idle_for", now.Sub(*scan.LastActivityAt)),
					zap.String("stream", work.Stream),
					zap.String("group", work.Group),
					zap.Int64("pending", work.Pending),
					zap.Duration("youngest_pending_idle", work.YoungestIdle),
				)
			}
		}

		complete, reason := p.decideCompletion(scanAge, scan.LastActivityAt, quiescent, inFlight, now)
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
		if reason != shared.ScanCompletionPipelineQuiescent {
			m.logger.Warn("Scan closed by a timeout before its pipeline drained; marking as done without reconciling findings", logFields...)
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
		m.markDone(ctx, scan.ID, reason)
	}

	span.SetStatus(codes.Ok, "")

	return nil
}

// scanStartTime is when the scan's pipeline started. A scan queued by the web UI
// can wait behind another scan, so its created_at is not its start; started_at
// is set when the coordinator claims it. Older scans have no started_at.
func scanStartTime(scan shared.Scan) time.Time {
	if scan.StartedAt != nil {
		return *scan.StartedAt
	}
	return scan.CreatedAt
}

// decideCompletion is the pure completion decision for a single scan, factored out so the
// full truth table can be unit-tested without Redis or MongoDB. Paths, in precedence order:
//
//  1. safety_timeout   — scanAge > safetyTimeout (3h). Force-complete.
//  2. pipeline_quiescent — the scan has run past minRuntime, ingestion has produced work
//     and been quiet for settleGrace, AND every scan-pipeline stream/group has drained
//     (no pending AND no undelivered entries).
//  3. idle_timeout     — a backstop for a stuck or never-created group where quiescence can
//     never be satisfied: no ingestion activity for idleTimeout after minRuntime, AND no
//     watched group holds work in flight (a pending entry delivered less than stuckAfter
//     ago). A long discovery job publishes nothing for minutes while it works; without the
//     in-flight guard it was closed here, and its late results arrived after finding
//     resolution.
//
// Only pipeline_quiescent means the scan saw everything it was going to see. Both timeouts
// close a scan whose pipeline had not drained, so they never reconcile findings (see
// reconcileFindings).
//
// A scan that never produced any activity (LastActivityAt == nil) is intentionally closed only
// by the safety timeout — we never want to complete a scan that has shown no sign of work.
func (p completionPolicy) decideCompletion(scanAge time.Duration, lastActivityAt *time.Time, quiescent, workInFlight bool, now time.Time) (complete bool, reason string) {
	if scanAge > p.safetyTimeout {
		return true, shared.ScanCompletionSafetyTimeout
	}

	if quiescent && p.quiescenceGuardsMet(scanAge, lastActivityAt, now) {
		return true, shared.ScanCompletionPipelineQuiescent
	}

	if !workInFlight && p.idleGuardsMet(scanAge, lastActivityAt, now) {
		return true, shared.ScanCompletionIdleTimeout
	}

	return false, ""
}

// reconcileFindings decides whether a closing scan may resolve findings at all. A false
// resolution tells a customer an unfixed vulnerability is fixed, so only a pipeline_quiescent
// close resolves: a timeout closes a scan whose evidence may still be in flight. Even then a
// finding is resolved only on positive evidence (decideResolutions).
func reconcileFindings(completionReason string) (ok bool, skip string) {
	if completionReason != shared.ScanCompletionPipelineQuiescent {
		return false, "closed by " + completionReason + " before the pipeline drained"
	}
	return true, ""
}

// quiescenceGuardsMet reports whether a scan is old enough and has been quiet long enough that
// a "pipeline drained" reading can be trusted to mean "done" rather than "hasn't started yet."
// settleGrace is larger than the ingestion activity-write throttle so a scan that is merely
// between throttled activity writes is not mistaken for settled.
func (p completionPolicy) quiescenceGuardsMet(scanAge time.Duration, lastActivityAt *time.Time, now time.Time) bool {
	return scanAge > p.minRuntime &&
		lastActivityAt != nil &&
		now.Sub(*lastActivityAt) > p.settleGrace
}

// idleGuardsMet reports whether the scan is past minRuntime and has had no ingestion activity
// for idleTimeout — the idle timeout applies unless work is in flight.
func (p completionPolicy) idleGuardsMet(scanAge time.Duration, lastActivityAt *time.Time, now time.Time) bool {
	return scanAge > p.minRuntime &&
		lastActivityAt != nil &&
		now.Sub(*lastActivityAt) > p.idleTimeout
}

// pendingWork describes the group that holds work in flight.
type pendingWork struct {
	StreamGroup
	Pending      int64
	YoungestIdle time.Duration
}

// freshPendingWork returns the first group that has a pending entry delivered less than
// stuckAfter ago, or nil. Such an entry is a job a live consumer is still working on. When
// every pending entry is older, the consumers are treated as stuck. The youngest entry counts,
// not the oldest: entries a consumer read ahead and holds behind a long job get old without
// meaning anything is stuck.
func freshPendingWork(ctx context.Context, info streamInfo, groups []StreamGroup, stuckAfter time.Duration) (*pendingWork, error) {
	for _, sg := range groups {
		present, err := info.groups(ctx, sg.Stream)
		if err != nil {
			return nil, err
		}
		g, ok := present[sg.Group]
		if !ok || g.Pending == 0 {
			continue
		}
		idles, err := info.pendingIdle(ctx, sg.Stream, sg.Group, g.Pending)
		if err != nil {
			return nil, err
		}
		if len(idles) == 0 {
			continue
		}
		youngest := slices.Min(idles)
		if youngest < stuckAfter {
			return &pendingWork{StreamGroup: sg, Pending: g.Pending, YoungestIdle: youngest}, nil
		}
	}
	return nil, nil
}

// pipelineQuiescent reports whether every group in scanPipelineGroups() has fully drained its
// stream: nothing pending (read-but-unacked) AND nothing undelivered (last-delivered id == the
// stream's last-generated id).
//
// The undelivered check catches triggers sitting unread while a single-threaded scanner
// (nuclei) works its backlog; an XPending-only check marked scans "done" ~30s in. The check is
// stream-wide, not scan-scoped, so a concurrent scan can only delay completion, never cause a
// false one.
func (m *ScanMonitor) pipelineQuiescent(ctx context.Context) (bool, error) {
	return pipelineQuiescent(ctx, redisStreamInfo{m.redis}, scanPipelineGroups())
}

// streamInfo reads the state of a stream and its consumer groups.
type streamInfo interface {
	// lastGeneratedID returns the stream's last-generated id, "0-0" for a missing stream.
	lastGeneratedID(ctx context.Context, stream string) (string, error)
	// groups returns the stream's consumer groups by name, empty for a missing stream.
	groups(ctx context.Context, stream string) (map[string]redis.XInfoGroup, error)
	// pendingIdle returns the time since last delivery of up to count pending entries.
	pendingIdle(ctx context.Context, stream, group string, count int64) ([]time.Duration, error)
}

// pipelineQuiescent checks the groups one at a time, in the given order, and reads each
// stream again for each group. With the upstream-first order of scanPipelineGroups(), a stage
// that ACKs its last job between two reads has already published its results, and the later
// read of the downstream stream sees them.
func pipelineQuiescent(ctx context.Context, info streamInfo, groups []StreamGroup) (bool, error) {
	for _, sg := range groups {
		lastGenerated, err := info.lastGeneratedID(ctx, sg.Stream)
		if err != nil {
			return false, err
		}
		present, err := info.groups(ctx, sg.Stream)
		if err != nil {
			return false, err
		}

		group, ok := present[sg.Group]
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
	return true, nil
}

// groupQuiescent reports whether a single consumer group has drained a stream: nothing pending
// (read-but-unacked) and nothing undelivered (its last-delivered id equals the stream's
// last-generated id). Equality — not ordering — is used deliberately: Redis stream IDs are not
// zero-padded, so lexicographic comparison is unsafe.
func groupQuiescent(pending int64, lastDeliveredID, lastGeneratedID string) bool {
	return pending == 0 && lastDeliveredID == lastGeneratedID
}

type redisStreamInfo struct{ rdb *redis.Client }

func (r redisStreamInfo) pendingIdle(ctx context.Context, stream, group string, count int64) ([]time.Duration, error) {
	entries, err := r.rdb.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: stream, Group: group, Start: "-", End: "+", Count: min(count, 1000),
	}).Result()
	if err != nil {
		return nil, err
	}
	idles := make([]time.Duration, len(entries))
	for i, e := range entries {
		idles[i] = e.Idle
	}
	return idles, nil
}

// lastGeneratedID returns the stream's last-generated entry id, or the empty-stream id
// ("0-0") if the stream does not exist yet.
func (r redisStreamInfo) lastGeneratedID(ctx context.Context, stream string) (string, error) {
	info, err := r.rdb.XInfoStream(ctx, stream).Result()
	if err != nil {
		if isNoSuchKeyErr(err) {
			return "0-0", nil
		}
		return "", err
	}
	return info.LastGeneratedID, nil
}

// groups returns the consumer groups on a stream keyed by name. A missing stream yields an
// empty map (no groups), not an error.
func (r redisStreamInfo) groups(ctx context.Context, stream string) (map[string]redis.XInfoGroup, error) {
	groups, err := r.rdb.XInfoGroups(ctx, stream).Result()
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

// markDone marks a scan as done with its completion reason and, when reconcileFindings
// allows it, resolves the open findings that the scan's evidence proves gone
// (findingsToResolve). The web UI polls the scan document for the status change.
func (m *ScanMonitor) markDone(ctx context.Context, scanID, reason string) error {
	// Read the scan now, not from the monitor tick's listing: a degraded asset that ingestion
	// recorded after that listing, but before the pipeline read as drained, must count.
	var scan shared.Scan
	stats := &shared.ScanStats{}
	err := m.db.Collection(shared.CollectionScans).FindOne(ctx, bson.M{"_id": scanID}).Decode(&scan)
	if err == nil {
		stats, err = m.computeStats(ctx, scan)
	}
	if err != nil {
		m.logger.Error("Failed to compute scan statistics",
			zap.String("scan_id", scanID),
			zap.Error(err),
		)
		// Continue with marking the scan as done even if stats computation fails.
		stats = &shared.ScanStats{}
	}

	reconcile, skip := reconcileFindings(reason)
	var decision resolutionDecision
	if reconcile && scan.ID != "" && !slices.Contains(startedStatuses, scan.Status) {
		// Another writer closed the scan (for example as failed): it resolves nothing.
		reconcile, skip = false, "scan was already closed as "+scan.Status
	} else if reconcile && scan.ID != "" {
		decision, err = m.findingsToResolve(ctx, scan)
		if err != nil {
			m.logger.Error("Failed to select the findings to resolve",
				zap.String("scan_id", scanID), zap.Error(err))
			reconcile, skip = false, "could not select the findings to resolve"
			decision = resolutionDecision{}
		}
	} else if reconcile {
		reconcile, skip = false, "could not read the scan"
	}

	// Resolve before closing the scan, so the scan's counts are what was written.
	resolved := 0
	if reconcile {
		resolved = m.resolve(ctx, scan, decision)
	}
	stats.ResolvedFindings = resolved
	stats.UncheckedFindings = len(decision.unchecked)

	now := time.Now()
	set := bson.M{
		"status":            shared.StatusDone,
		"completion_reason": reason,
		// A scan that drained with every asset fully checked. The web app shows the others
		// as partial. Finding resolution does not depend on it.
		"findings_reconciled":        reconcile && len(scan.DegradedAssets) == 0,
		"completed_at":               now,
		"updated_at":                 now,
		"stats.total_discoveries":    stats.TotalDiscoveries,
		"stats.new_discoveries":      stats.NewDiscoveries,
		"stats.resolved_discoveries": stats.ResolvedDiscoveries,
		"stats.total_findings":       stats.TotalFindings,
		"stats.new_findings":         stats.NewFindings,
		"stats.resolved_findings":    stats.ResolvedFindings,
		"stats.unchecked_findings":   stats.UncheckedFindings,
	}
	if len(decision.unchecked) > 0 {
		set["unchecked_finding_ids"] = decision.unchecked
	}

	// The status guard keeps a scan that another writer already closed (for
	// example as failed) from being reopened as done.
	result, err := m.db.Collection(shared.CollectionScans).UpdateOne(
		ctx,
		bson.M{"_id": scanID, "status": bson.M{"$in": startedStatuses}},
		bson.M{"$set": set},
	)
	if err != nil {
		m.logger.Error("Failed to mark scan as done",
			zap.String("scan_id", scanID),
			zap.Error(err),
		)
		return err
	}
	if result.ModifiedCount == 0 {
		return nil
	}
	m.logger.Info("Scan marked as done",
		zap.String("scan_id", scanID),
		zap.String("completion_reason", reason),
		zap.Int("resolved_findings", stats.ResolvedFindings),
		zap.Int("unchecked_findings", stats.UncheckedFindings),
		zap.Int("degraded_assets", len(scan.DegradedAssets)),
		zap.Time("completed_at", now),
	)
	if !reconcile {
		m.logger.Warn("Skipping finding resolution",
			zap.String("scan_id", scanID),
			zap.String("why", skip),
		)
	}
	return nil
}

// resolve writes the decision and returns how many findings it resolved. Errors are logged:
// the findings stay open and the scan still closes.
func (m *ScanMonitor) resolve(ctx context.Context, scan shared.Scan, d resolutionDecision) int {
	ctx, span := m.tracer.Start(ctx, "resolve_findings",
		trace.WithAttributes(
			attribute.String("scan.id", scan.ID),
			attribute.Int("findings.not_reproduced", len(d.notReproduced)),
			attribute.Int("findings.host_no_longer_found", len(d.gone)),
			attribute.Int("findings.unchecked", len(d.unchecked)),
		),
	)
	defer span.End()

	var total int64
	for _, batch := range []struct {
		ids    []string
		reason string
	}{
		{d.notReproduced, ResolutionNotReproduced},
		{d.gone, ResolutionHostNoLongerFound},
	} {
		n, err := m.resolveFindings(ctx, scan, batch.ids, batch.reason)
		if err != nil {
			m.logger.Error("Failed to mark findings as resolved",
				zap.String("scan_id", scan.ID),
				zap.String("resolution_reason", batch.reason),
				zap.Int("count", len(batch.ids)),
				zap.Error(err),
			)
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to resolve findings")
			continue
		}
		total += n
		if len(batch.ids) > 0 {
			m.logger.Info("Marked findings as resolved",
				zap.String("scan_id", scan.ID),
				zap.String("resolution_reason", batch.reason),
				zap.Int("expected", len(batch.ids)),
				zap.Int64("updated", n),
			)
		}
	}
	return int(total)
}
