package scan_coordinator

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TestQueueScanAgainstMongo checks the cron's queued scan against a real MongoDB with the web
// app's one-queued-scan-per-org index (MongoDbIndexManager, org_id_1_queued_unique). Set
// VULWALL_TEST_MONGO_URI to run it.
func TestQueueScanAgainstMongo(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_MONGO_URI not set")
	}
	ctx := context.Background()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database("vulwall_test_" + uuid.NewString()[:8])
	t.Cleanup(func() { _ = db.Drop(ctx); _ = client.Disconnect(ctx) })

	scans := db.Collection(shared.CollectionScans)
	if _, err := scans.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "org_id", Value: 1}},
		Options: options.Index().SetName("org_id_1_queued_unique").SetUnique(true).
			SetPartialFilterExpression(bson.M{"status": shared.StatusQueued}),
	}); err != nil {
		t.Fatal(err)
	}
	const org = "org-1"
	if _, err := db.Collection(shared.CollectionOrganizations).InsertOne(ctx, bson.M{"_id": org,
		"scan_settings": bson.M{"scan_cron": "0 2 * * *", "enabled": false}}); err != nil {
		t.Fatal(err)
	}
	if _, err := scans.InsertOne(ctx, bson.M{"_id": "r1", "org_id": org, "status": shared.StatusRunning, "created_at": time.Now()}); err != nil {
		t.Fatal(err)
	}

	store := mongoScanStore{db: db}
	svc, _ := newTestService(store, nil)
	req := ScanRequest{OrgID: org, Type: shared.ScanTypeScheduled, TriggeredBy: "system"}

	scanID, err := svc.TriggerScan(ctx, req)
	if !errors.Is(err, ErrScanQueued) {
		t.Fatalf("err = %v, want ErrScanQueued", err)
	}
	var got bson.M
	if err := scans.FindOne(ctx, bson.M{"_id": scanID}).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["status"] != shared.StatusQueued || got["type"] != shared.ScanTypeScheduled || got["triggered_by"] != "system" {
		t.Fatalf("queued scan = %v", got)
	}

	// The index rejects a second queued scan, and the service reads that as "already queued".
	err = store.insertScan(ctx, shared.Scan{ID: "q2", OrgID: org, Status: shared.StatusQueued})
	if !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("second queued insert err = %v, want duplicate key", err)
	}
	if _, err := svc.queueScan(ctx, req); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("queueScan err = %v, want ErrScanInProgress", err)
	}
	if n, _ := scans.CountDocuments(ctx, bson.M{"org_id": org, "status": shared.StatusQueued}); n != 1 {
		t.Fatalf("%d queued scans, want 1", n)
	}

	// The delete filters on status too, so a running scan is never deleted.
	if deleted, err := store.deleteQueuedScan(ctx, "r1"); err != nil || deleted {
		t.Fatalf("deleteQueuedScan(running) = %v, %v; want false, nil", deleted, err)
	}

	// The schedule is off: when the running scan is done, the poller deletes the queued
	// scheduled scan instead of running it.
	if _, err := scans.UpdateOne(ctx, bson.M{"_id": "r1"}, bson.M{"$set": bson.M{"status": shared.StatusDone}}); err != nil {
		t.Fatal(err)
	}
	svc.startQueuedScans(ctx)
	if n, _ := scans.CountDocuments(ctx, bson.M{"_id": scanID}); n != 0 {
		t.Fatalf("queued scheduled scan still exists after the schedule was turned off")
	}
	if n, _ := scans.CountDocuments(ctx, bson.M{"_id": "r1"}); n != 1 {
		t.Fatalf("finished scan r1 was removed")
	}
}
