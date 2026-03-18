package scan_coordinator

import (
	"context"
	"encoding/json"
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
	redis    *redis.Client
	db       *mongo.Database
	logger   *zap.Logger
	webhook  *WebhookNotifier
	tracer   trace.Tracer
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

// Start begins monitoring scans every 15 minutes
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

	for _, scan := range scans {
		scanAge := time.Since(scan.CreatedAt)

		// 1. Safety timeout (3 hours) — absolute upper bound for stuck scans
		if scanAge > ScanSafetyTimeout {
			m.logger.Warn("Scan safety timeout reached, marking as done",
				zap.String("scan_id", scan.ID),
				zap.Duration("age", scanAge),
			)
			span.AddEvent("scan_completed",
				trace.WithAttributes(
					attribute.String("scan.id", scan.ID),
					attribute.String("org.id", scan.OrgID),
					attribute.String("completion_reason", "safety_timeout"),
					attribute.String("scan.duration", scanAge.String()),
				),
			)
			m.markDone(ctx, scan.ID, true)
			continue
		}

		// 2. Check if all consumer groups have processed this scan (fastest path)
		if m.isComplete(ctx, scan.ID) {
			m.logger.Info("Scan complete, all consumers finished",
				zap.String("scan_id", scan.ID),
				zap.Duration("duration", scanAge),
			)
			span.AddEvent("scan_completed",
				trace.WithAttributes(
					attribute.String("scan.id", scan.ID),
					attribute.String("org.id", scan.OrgID),
					attribute.String("completion_reason", "all_consumers_finished"),
					attribute.String("scan.duration", scanAge.String()),
				),
			)
			m.markDone(ctx, scan.ID, false)
			continue
		}

		// 3. Idle detection — no new activity for 15 min (ingestion has settled)
		if scanAge > ScanMinRuntime && scan.LastActivityAt != nil {
			idleDuration := time.Since(*scan.LastActivityAt)
			if idleDuration > ScanIdleTimeout {
				m.logger.Info("Scan idle timeout reached, ingestion has settled",
					zap.String("scan_id", scan.ID),
					zap.Duration("age", scanAge),
					zap.Duration("idle_for", idleDuration),
					zap.Time("last_activity", *scan.LastActivityAt),
				)
				span.AddEvent("scan_completed",
					trace.WithAttributes(
						attribute.String("scan.id", scan.ID),
						attribute.String("org.id", scan.OrgID),
						attribute.String("completion_reason", "idle_timeout"),
						attribute.String("scan.duration", scanAge.String()),
						attribute.String("idle_duration", idleDuration.String()),
					),
				)
				m.markDone(ctx, scan.ID, false) // Safe to resolve — ingestion settled
				continue
			}
		}
	}

	span.SetStatus(codes.Ok, "")

	return nil
}

// isComplete checks if all consumer groups have 0 pending messages for this scan
func (m *ScanMonitor) isComplete(ctx context.Context, scanID string) bool {
	consumerGroups := []struct {
		stream string
		group  string
	}{
		// domain_scan_triggers consumers (active recon scanners on domains/subdomains)
		{shared.StreamDomainScanTriggers, "nuclei_scanner_service"},
		{shared.StreamDomainScanTriggers, "testssl_scanner_service"},
		{shared.StreamDomainScanTriggers, "webtechprofiler_service"},
		{shared.StreamDomainScanTriggers, "js_dependency_scanner_service"},
		{shared.StreamDomainScanTriggers, "http_header_scanner_service"},
		{shared.StreamDomainScanTriggers, "email_security_scanner_service"},

		// port_scan_triggers consumers (active recon scanners on ports)
		{shared.StreamPortScanTriggers, "nuclei_scanner_service"},

		// domain_discovery_results consumers (ingestion)
		{shared.StreamDomainDiscoveryResults, "domain_ingestion_service"},

		// ip_discovery_results consumers (ingestion + webtechprofiler)
		{shared.StreamIPDiscoveryResults, "port_ingestion_service"},
		{shared.StreamIPDiscoveryResults, "webtechprofiler_service"},

		// security_findings consumers (findings ingestion to MongoDB)
		{shared.StreamSecurityFindings, "findings_ingestion_service"},
	}

	var pendingGroups []string
	for _, cg := range consumerGroups {
		if m.hasPendingForScan(ctx, cg.stream, cg.group, scanID) {
			pendingGroups = append(pendingGroups, cg.group+" ("+cg.stream+")")
		}
	}

	if len(pendingGroups) > 0 {
		m.logger.Debug("Scan has pending consumer groups",
			zap.String("scan_id", scanID),
			zap.Int("pending_count", len(pendingGroups)),
			zap.Strings("pending_groups", pendingGroups),
		)
		return false
	}

	return true // All consumer groups have 0 pending for this scan
}

// hasPendingForScan checks if a consumer group has pending messages for this scan_id
func (m *ScanMonitor) hasPendingForScan(ctx context.Context, stream, group, scanID string) bool {
	// Get pending count for this consumer group
	pending, err := m.redis.XPending(ctx, stream, group).Result()
	if err != nil || pending.Count == 0 {
		return false
	}

	// Get detailed pending info (check up to 100 pending messages)
	pendingExt, err := m.redis.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: stream,
		Group:  group,
		Start:  "-",
		End:    "+",
		Count:  100,
	}).Result()

	if err != nil || len(pendingExt) == 0 {
		return false
	}

	// Check if any pending message has this scan_id
	for _, msg := range pendingExt {
		messages, err := m.redis.XRange(ctx, stream, msg.ID, msg.ID).Result()
		if err != nil || len(messages) == 0 {
			continue
		}

		data, ok := messages[0].Values["data"].(string)
		if !ok {
			continue
		}

		var finding map[string]interface{}
		if err := json.Unmarshal([]byte(data), &finding); err != nil {
			continue
		}

		// Check if this finding has the scan_id
		if scanIDVal, ok := finding["scan_id"]; ok && scanIDVal == scanID {
			m.logger.Debug("Found pending message for scan",
				zap.String("scan_id", scanID),
				zap.String("stream", stream),
				zap.String("group", group),
			)
			return true // Found pending message for this scan
		}
	}

	return false
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
			"status":                      shared.StatusDone,
			"completed_at":                now,
			"updated_at":                  now,
			"stats.total_discoveries":     stats.TotalDiscoveries,
			"stats.new_discoveries":       stats.NewDiscoveries,
			"stats.resolved_discoveries":  stats.ResolvedDiscoveries,
			"stats.total_findings":        stats.TotalFindings,
			"stats.new_findings":          stats.NewFindings,
			"stats.resolved_findings":     stats.ResolvedFindings,
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

		// Mark disappeared findings as resolved (skip on timeout — ingestion may be incomplete)
		if timedOut {
			m.logger.Warn("Skipping finding resolution for timed-out scan",
				zap.String("scan_id", scanID),
				zap.Int("would_resolve", len(resolvedFindingIDs)),
			)
		} else {
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
			"resolved_at":        now,
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
