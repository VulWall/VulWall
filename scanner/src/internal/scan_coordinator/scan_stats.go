package scan_coordinator

import (
	"context"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// computeStats computes scan statistics by comparing current scan results with the previous
// completed scan. It does not set ResolvedFindings or UncheckedFindings: markDone counts
// those from its resolution decision, which does not depend on the previous scan.
func (m *ScanMonitor) computeStats(ctx context.Context, currentScan shared.Scan) (*shared.ScanStats, error) {
	scanID := currentScan.ID

	m.logger.Debug("Computing stats for scan",
		zap.String("scan_id", scanID),
		zap.String("org_id", currentScan.OrgID),
	)

	// 2. Get current scan's discovery IDs
	currentDiscoveryIDs, err := m.getDiscoveryIDsForScan(ctx, currentScan.OrgID, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current discovery IDs: %w", err)
	}

	// 3. Get current scan's finding IDs
	currentFindingIDs, err := m.getFindingIDsForScan(ctx, currentScan.OrgID, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current finding IDs: %w", err)
	}

	// 4. Find the previous completed scan for this organization, the baseline of the new/
	// resolved counters. A scan closed before its pipeline drained saw an unknown part of the
	// attack surface, so it is no baseline: what it missed would count as new. Scans closed
	// before completion_reason existed have no field and match.
	filter := bson.M{
		"org_id":     currentScan.OrgID,
		"status":     shared.StatusDone,
		"created_at": bson.M{"$lt": currentScan.CreatedAt},
		"$or": bson.A{
			bson.M{"completion_reason": shared.ScanCompletionPipelineQuiescent},
			bson.M{"completion_reason": bson.M{"$exists": false}},
		},
	}
	opts := options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}})

	var previousScan shared.Scan
	err = m.db.Collection(shared.CollectionScans).FindOne(ctx, filter, opts).Decode(&previousScan)

	stats := &shared.ScanStats{
		TotalAssets:      currentScan.Stats.TotalAssets, // Keep existing total_assets
		TotalDiscoveries: len(currentDiscoveryIDs),
		TotalFindings:    len(currentFindingIDs),
	}

	if err != nil {
		// No previous scan found - this is the first scan for the organization
		m.logger.Info("No previous scan found, all discoveries and findings are new",
			zap.String("scan_id", scanID),
			zap.String("org_id", currentScan.OrgID),
		)

		stats.NewDiscoveries = len(currentDiscoveryIDs)
		stats.NewFindings = len(currentFindingIDs)
		stats.ResolvedDiscoveries = 0

		return stats, nil
	}

	m.logger.Debug("Found previous scan for comparison",
		zap.String("scan_id", scanID),
		zap.String("previous_scan_id", previousScan.ID),
	)

	// 5. Get previous scan's discovery and finding IDs
	previousDiscoveryIDs, err := m.getDiscoveryIDsForScan(ctx, currentScan.OrgID, previousScan.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous discovery IDs: %w", err)
	}

	previousFindingIDs, err := m.getFindingIDsForScan(ctx, currentScan.OrgID, previousScan.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous finding IDs: %w", err)
	}

	// 6. Compute set differences using maps for efficiency
	// For discoveries: only need counts (no status update needed)
	stats.NewDiscoveries = setDifference(currentDiscoveryIDs, previousDiscoveryIDs)
	stats.ResolvedDiscoveries = setDifference(previousDiscoveryIDs, currentDiscoveryIDs)

	stats.NewFindings = setDifference(currentFindingIDs, previousFindingIDs)

	m.logger.Info("Computed scan statistics",
		zap.String("scan_id", scanID),
		zap.Int("total_discoveries", stats.TotalDiscoveries),
		zap.Int("new_discoveries", stats.NewDiscoveries),
		zap.Int("resolved_discoveries", stats.ResolvedDiscoveries),
		zap.Int("total_findings", stats.TotalFindings),
		zap.Int("new_findings", stats.NewFindings),
	)

	return stats, nil
}

// getDiscoveryIDsForScan retrieves all discovery IDs that contain the given scan ID in their scan_ids array
func (m *ScanMonitor) getDiscoveryIDsForScan(ctx context.Context, orgID, scanID string) ([]string, error) {
	filter := bson.M{
		"org_id":   orgID,
		"scan_ids": scanID,
	}

	projection := bson.M{"_id": 1}

	cursor, err := m.db.Collection(shared.CollectionDiscoveries).Find(ctx, filter, options.Find().SetProjection(projection))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var ids []string
	for cursor.Next(ctx) {
		var result struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&result); err != nil {
			return nil, err
		}
		ids = append(ids, result.ID)
	}

	return ids, cursor.Err()
}

// getFindingIDsForScan retrieves all finding IDs that contain the given scan ID in their scan_ids array
func (m *ScanMonitor) getFindingIDsForScan(ctx context.Context, orgID, scanID string) ([]string, error) {
	filter := bson.M{
		"org_id":   orgID,
		"scan_ids": scanID,
	}

	projection := bson.M{"_id": 1}

	cursor, err := m.db.Collection(shared.CollectionFindings).Find(ctx, filter, options.Find().SetProjection(projection))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var ids []string
	for cursor.Next(ctx) {
		var result struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&result); err != nil {
			return nil, err
		}
		ids = append(ids, result.ID)
	}

	return ids, cursor.Err()
}

// setDifference returns the count of elements in set A that are not in set B (|A - B|)
// Optimized using maps for O(n) performance
func setDifference(setA, setB []string) int {
	// Build map of set B for O(1) lookups
	setBMap := make(map[string]bool, len(setB))
	for _, item := range setB {
		setBMap[item] = true
	}

	// Count items in A that are not in B
	count := 0
	for _, item := range setA {
		if !setBMap[item] {
			count++
		}
	}

	return count
}
