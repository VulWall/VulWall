package shared

import (
	"context"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// ActivityUpdateInterval controls how often last_activity_at is written to MongoDB
// per scan. Updates within this window are coalesced to avoid excessive writes.
const ActivityUpdateInterval = 30 * time.Second

// ScanActivityTracker updates scan.last_activity_at in MongoDB with in-memory
// throttling. Each scan ID is updated at most once per ActivityUpdateInterval,
// preventing ingestion from hammering MongoDB with per-message updates.
//
// Thread-safe: multiple goroutines may call TouchActivity concurrently.
type ScanActivityTracker struct {
	db     *mongo.Database
	logger *zap.Logger

	mu       sync.Mutex
	lastSent map[string]time.Time // scanID -> last MongoDB write time
}

// NewScanActivityTracker creates a new activity tracker.
func NewScanActivityTracker(db *mongo.Database, logger *zap.Logger) *ScanActivityTracker {
	return &ScanActivityTracker{
		db:       db,
		logger:   logger,
		lastSent: make(map[string]time.Time),
	}
}

// TouchActivity signals that ingestion activity occurred for the given scan.
// The MongoDB write is throttled: at most one write per ActivityUpdateInterval
// per scan ID. Callers should invoke this once per batch or processing loop
// iteration -- not on every individual message.
func (t *ScanActivityTracker) TouchActivity(ctx context.Context, scanID string) {
	if scanID == "" {
		return
	}

	now := time.Now()

	t.mu.Lock()
	last, exists := t.lastSent[scanID]
	if exists && now.Sub(last) < ActivityUpdateInterval {
		t.mu.Unlock()
		return // Throttled -- skip this write
	}
	t.lastSent[scanID] = now
	t.mu.Unlock()

	// Fire-and-forget MongoDB update. Errors are logged but do not propagate
	// to callers -- scan activity tracking is best-effort.
	_, err := t.db.Collection(CollectionScans).UpdateOne(ctx,
		bson.M{"_id": scanID},
		bson.M{"$set": bson.M{"last_activity_at": now}},
	)
	if err != nil {
		t.logger.Warn("Failed to update scan last_activity_at",
			zap.String("scan_id", scanID),
			zap.Error(err),
		)
	}
}
