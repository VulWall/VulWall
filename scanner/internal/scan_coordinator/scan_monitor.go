package scan_coordinator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// ScanMonitor monitors scan completion and marks scans as done
type ScanMonitor struct {
	redis  *redis.Client
	db     *mongo.Database
	logger *zap.Logger
}

// NewScanMonitor creates a new scan monitor
func NewScanMonitor(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *ScanMonitor {
	return &ScanMonitor{
		redis:  redisClient,
		db:     db,
		logger: logger,
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
	// Find scans with status="pending" or "running"
	filter := bson.M{
		"status": bson.M{"$in": []string{shared.StatusPending, shared.StatusRunning}},
	}

	cursor, err := m.db.Collection(shared.CollectionScans).Find(ctx, filter)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)

	var scans []shared.Scan
	if err := cursor.All(ctx, &scans); err != nil {
		return err
	}

	if len(scans) > 0 {
		m.logger.Info("Monitoring scans", zap.Int("active_scans", len(scans)))
	}

	for _, scan := range scans {
		// Check timeout (30 minutes since creation)
		if time.Since(scan.CreatedAt) > 30*time.Minute {
			m.logger.Info("Scan timeout reached, marking as done",
				zap.String("scan_id", scan.ID),
				zap.Duration("age", time.Since(scan.CreatedAt)),
			)
			m.markDone(ctx, scan.ID)
			continue
		}

		// Check if all consumer groups have processed this scan
		if m.isComplete(ctx, scan.ID) {
			m.logger.Info("Scan complete, all consumers finished",
				zap.String("scan_id", scan.ID),
				zap.Duration("duration", time.Since(scan.CreatedAt)),
			)
			m.markDone(ctx, scan.ID)
		}
	}

	return nil
}

// isComplete checks if all consumer groups have 0 pending messages for this scan
func (m *ScanMonitor) isComplete(ctx context.Context, scanID string) bool {
	consumerGroups := []struct {
		stream string
		group  string
	}{
		// domain_discovery_results consumers
		{shared.StreamDomainDiscoveryResults, "domain_ingestion_service"},
		{shared.StreamDomainDiscoveryResults, "nuclei_scanner_service"},
		{shared.StreamDomainDiscoveryResults, "testssl_scanner_service"},
		{shared.StreamDomainDiscoveryResults, "webtechprofiler_service"},

		// ip_discovery_results consumers
		{shared.StreamIPDiscoveryResults, "port_ingestion_service"},
		{shared.StreamIPDiscoveryResults, "nuclei_scanner_service"},
		{shared.StreamIPDiscoveryResults, "testssl_scanner_service"},
		{shared.StreamIPDiscoveryResults, "webtechprofiler_service"},
	}

	for _, cg := range consumerGroups {
		if m.hasPendingForScan(ctx, cg.stream, cg.group, scanID) {
			return false // Still has pending messages for this scan
		}
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

// markDone marks a scan as done
func (m *ScanMonitor) markDone(ctx context.Context, scanID string) error {
	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"status":       shared.StatusDone,
			"completed_at": now,
			"updated_at":   now,
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
	}

	return nil
}
