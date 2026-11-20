package findings_ingestion

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// testMongo connects to VULWALL_TEST_MONGO_URI and returns a throwaway database, or skips.
func testMongo(t *testing.T) *mongo.Database {
	t.Helper()
	uri := os.Getenv("VULWALL_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_MONGO_URI not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database("vulwall_test_" + uuid.NewString()[:8])
	t.Cleanup(func() {
		_ = db.Drop(context.Background())
		_ = client.Disconnect(context.Background())
	})
	return db
}

func TestCoverageUpdateMergesRunsAndErrorWins(t *testing.T) {
	db := testMongo(t)
	ctx := context.Background()
	coll := db.Collection(shared.CollectionScanCoverage)
	filter := bson.M{"scan_id": "s1", "source": "nuclei", "discovery_id": "d1"}
	upsert := options.Update().SetUpsert(true)
	run := func(cov shared.ScanCoverage) {
		t.Helper()
		if _, err := coll.UpdateOne(ctx, filter, coverageUpdate("org", cov, time.Now()), upsert); err != nil {
			t.Fatal(err)
		}
	}
	a := shared.FindingKey{FindingType: "cve-1", Title: "A"}
	b := shared.FindingKey{FindingType: "cve-2", Title: "B"}

	run(shared.ScanCoverage{Source: "nuclei", DiscoveryID: "d1", Status: shared.CoverageOK, Reported: []shared.FindingKey{a}})
	run(shared.ScanCoverage{Source: "nuclei", DiscoveryID: "d1", Status: shared.CoverageOK, Reported: []shared.FindingKey{a, b}}) // redelivery / second trigger

	var rec struct {
		Status   string              `bson:"status"`
		Reported []shared.FindingKey `bson:"reported"`
		OrgID    string              `bson:"org_id"`
	}
	if err := coll.FindOne(ctx, filter).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if n, _ := coll.CountDocuments(ctx, bson.M{}); n != 1 {
		t.Fatalf("records = %d, want 1 per (scan, source, target)", n)
	}
	if rec.Status != shared.CoverageOK || len(rec.Reported) != 2 || rec.OrgID != "org" {
		t.Fatalf("after two ok runs: %+v, want ok with the union of reported keys", rec)
	}

	run(shared.ScanCoverage{Source: "nuclei", DiscoveryID: "d1", Status: shared.CoverageError, Error: "timeout"})
	run(shared.ScanCoverage{Source: "nuclei", DiscoveryID: "d1", Status: shared.CoverageOK})
	if err := coll.FindOne(ctx, filter).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if rec.Status != shared.CoverageError {
		t.Fatalf("status = %q after an error run, want error to stick", rec.Status)
	}
}

// TestCoverageUpdateStoresDollarValuesLiterally: target, error and titles come from the
// scanned site; a value that starts with "$" must be stored as written, not evaluated.
func TestCoverageUpdateStoresDollarValuesLiterally(t *testing.T) {
	db := testMongo(t)
	ctx := context.Background()
	coll := db.Collection(shared.CollectionScanCoverage)
	filter := bson.M{"scan_id": "s1", "source": "nuclei", "discovery_id": "d1"}
	key := shared.FindingKey{FindingType: "$status", Title: "$$ROOT"}
	cov := shared.ScanCoverage{Source: "nuclei", DiscoveryID: "d1", Target: "$scan_id", Status: shared.CoverageOK, Reported: []shared.FindingKey{key}}
	for i := 0; i < 2; i++ {
		if _, err := coll.UpdateOne(ctx, filter, coverageUpdate("$org_id", cov, time.Now()), options.Update().SetUpsert(true)); err != nil {
			t.Fatal(err)
		}
	}
	errCov := cov
	errCov.Status, errCov.Error, errCov.Reported = shared.CoverageError, "$target", nil
	if _, err := coll.UpdateOne(ctx, filter, coverageUpdate("$org_id", errCov, time.Now())); err != nil {
		t.Fatal(err)
	}

	var rec struct {
		OrgID    string              `bson:"org_id"`
		Target   string              `bson:"target"`
		Error    string              `bson:"error"`
		Status   string              `bson:"status"`
		Reported []shared.FindingKey `bson:"reported"`
	}
	if err := coll.FindOne(ctx, filter).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if rec.OrgID != "$org_id" || rec.Target != "$scan_id" || rec.Error != "$target" || rec.Status != shared.CoverageError {
		t.Fatalf("record = %+v, want the values as written", rec)
	}
	if len(rec.Reported) != 1 || rec.Reported[0] != key {
		t.Fatalf("reported = %+v, want [%+v]", rec.Reported, key)
	}
}
