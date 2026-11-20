package demoseed

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func testDB(t *testing.T) (context.Context, *mongo.Database) {
	t.Helper()
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
	return ctx, db
}

func count(t *testing.T, ctx context.Context, db *mongo.Database, coll string, filter bson.M) int64 {
	t.Helper()
	n, err := db.Collection(coll).CountDocuments(ctx, filter)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestApplyAndReset seeds into a throwaway database (VULWALL_TEST_MONGO_URI) with an
// organization that already exists, runs the queries the web app's Overview and Discoveries
// pages run, and checks that Reset removes the sample data and nothing else.
func TestApplyAndReset(t *testing.T) {
	ctx, db := testDB(t)
	orgOID := primitive.NewObjectID()
	orgID := orgOID.Hex()
	if _, err := db.Collection(shared.CollectionOrganizations).InsertOne(ctx, bson.M{
		"_id": orgOID, "company_name": "Real Co", "scan_settings": bson.M{"scan_cron": "17 3 * * 4", "enabled": true},
		"created_at": testNow, "updated_at": testNow,
	}); err != nil {
		t.Fatal(err)
	}

	ds, err := Apply(ctx, db, Options{Now: testNow, Version: "v0.1.0"})
	if err != nil {
		t.Fatal(err)
	}

	// Documents decode into the scanner's own models.
	var scans []shared.Scan
	cur, err := db.Collection(shared.CollectionScans).Find(ctx, bson.M{"org_id": orgID, "status": "done"},
		options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := cur.All(ctx, &scans); err != nil {
		t.Fatal(err)
	}
	if len(scans) != len(ds.Scans) {
		t.Fatalf("done scans = %d, want %d", len(scans), len(ds.Scans))
	}
	var discoveries []shared.Discovery
	cur, err = db.Collection(shared.CollectionDiscoveries).Find(ctx, bson.M{"org_id": orgID})
	if err != nil {
		t.Fatal(err)
	}
	if err := cur.All(ctx, &discoveries); err != nil {
		t.Fatal(err)
	}

	// Overview: findings of the latest done scan, and its critical/high ones.
	latest := scans[0].ID
	if n := count(t, ctx, db, shared.CollectionFindings, bson.M{"org_id": orgID, "scan_ids": latest}); n == 0 {
		t.Error("no findings in the latest scan")
	}
	if n := count(t, ctx, db, shared.CollectionFindings, bson.M{"org_id": orgID, "scan_ids": latest,
		"severity": bson.M{"$in": bson.A{"critical", "high"}}}); n < 3 {
		t.Errorf("latest scan has %d critical/high findings", n)
	}
	// Discoveries: top-level rows, and IPs/ports of the latest scan.
	if n := count(t, ctx, db, shared.CollectionDiscoveries, bson.M{"org_id": orgID,
		"asset_type": bson.M{"$in": bson.A{"domain", "subdomain"}}}); n < 12 {
		t.Errorf("%d domains and subdomains", n)
	}
	if n := count(t, ctx, db, shared.CollectionDiscoveries, bson.M{"org_id": orgID, "asset_type": "ip",
		"parent_id": bson.M{"$exists": false}, "metadata.cdn_edge": "Cloudflare", "scan_ids": latest}); n != 1 {
		t.Errorf("%d top-level CDN edge IP rows, want 1", n)
	}
	if n := count(t, ctx, db, shared.CollectionDiscoveries, bson.M{"org_id": orgID, "asset_type": "port", "scan_ids": latest}); n == 0 {
		t.Error("no ports in the latest scan")
	}
	if n := count(t, ctx, db, collSuppressions, bson.M{"org_id": orgID, "active": true}); n != 2 {
		t.Errorf("%d suppressions, want 2", n)
	}
	var org bson.M
	if err := db.Collection(shared.CollectionOrganizations).FindOne(ctx, bson.M{"_id": orgOID}).Decode(&org); err != nil {
		t.Fatal(err)
	}
	if org["company_name"] != CompanyName || org["tour_completed"] != true {
		t.Errorf("organization not updated: %v", org)
	}

	// A second run replaces the sample data instead of doubling it.
	if _, err := Apply(ctx, db, Options{Now: testNow, Version: "v0.1.0"}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, ctx, db, shared.CollectionFindings, bson.M{}); n != int64(len(ds.Findings)) {
		t.Errorf("after a rerun: %d findings, want %d", n, len(ds.Findings))
	}

	// Real data: Apply refuses without Force; Reset keeps it.
	if _, err := db.Collection(shared.CollectionAssets).InsertOne(ctx, bson.M{"_id": primitive.NewObjectID(),
		"org_id": orgID, "type": "domain", "domain": "real.example", "enabled": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection(shared.CollectionScans).InsertOne(ctx, bson.M{"_id": "real-scan", "org_id": orgID, "status": "done"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ctx, db, Options{Now: testNow}); !errors.Is(err, ErrHasData) {
		t.Errorf("Apply with real assets: err = %v, want ErrHasData", err)
	}
	if _, err := Apply(ctx, db, Options{Now: testNow, Force: true}); err != nil {
		t.Errorf("Apply --force: %v", err)
	}

	// The web app saves the organization with a full replace (here: the tour flag).
	org["tour_completed"] = false
	if _, err := db.Collection(shared.CollectionOrganizations).ReplaceOne(ctx, bson.M{"_id": orgOID}, org); err != nil {
		t.Fatal(err)
	}

	res, err := Reset(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if res.OrgsRestored != 1 {
		t.Errorf("organizations restored = %d", res.OrgsRestored)
	}
	for _, coll := range demoCollections {
		if n := count(t, ctx, db, coll, bson.M{"demo": true}); n != 0 {
			t.Errorf("%s: %d demo documents left", coll, n)
		}
	}
	if n := count(t, ctx, db, shared.CollectionAssets, bson.M{"domain": "real.example"}); n != 1 {
		t.Error("Reset removed a real asset")
	}
	if n := count(t, ctx, db, shared.CollectionScans, bson.M{"_id": "real-scan"}); n != 1 {
		t.Error("Reset removed a real scan")
	}
	org = bson.M{}
	if err := db.Collection(shared.CollectionOrganizations).FindOne(ctx, bson.M{"_id": orgOID}).Decode(&org); err != nil {
		t.Fatal(err)
	}
	settings, _ := org["scan_settings"].(bson.M)
	if org["company_name"] != "Real Co" || settings["scan_cron"] != "17 3 * * 4" || org["tour_completed"] != nil ||
		count(t, ctx, db, collState, bson.M{}) != 0 {
		t.Errorf("organization not restored: %v", org)
	}
}

// Without an organization, Apply creates the one the web app would, and seeds into it.
func TestApplyCreatesTheOrganization(t *testing.T) {
	ctx, db := testDB(t)
	ds, err := Apply(ctx, db, Options{Now: testNow, Version: "v0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, ctx, db, shared.CollectionOrganizations, bson.M{}); n != 1 {
		t.Fatalf("%d organizations", n)
	}
	oid, err := primitive.ObjectIDFromHex(ds.OrgID)
	if err != nil {
		t.Fatalf("org_id %q is not an ObjectId hex: %v", ds.OrgID, err)
	}
	if n := count(t, ctx, db, shared.CollectionOrganizations, bson.M{"_id": oid, "company_name": CompanyName}); n != 1 {
		t.Error("organization not named")
	}
	var info bson.M
	if err := db.Collection("system_info").FindOne(ctx, bson.M{"_id": "scanner"}).Decode(&info); err != nil || info["version"] != "v0.1.0" {
		t.Errorf("system_info = %v, %v", info, err)
	}
}
