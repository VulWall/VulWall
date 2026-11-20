package findings_ingestion

import (
	"context"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.uber.org/zap"
)

// TestUpsertFindingUpdatesSeverityInPlace: a finding reported again under the same key with
// a higher severity and a new description (a certificate that comes closer to its expiry)
// updates the one finding instead of adding a second one.
func TestUpsertFindingUpdatesSeverityInPlace(t *testing.T) {
	db := testMongo(t)
	ctx := context.Background()
	s := &Service{db: db, logger: zap.NewNop()}
	scan1, scan2 := "scan-1", "scan-2"
	finding := shared.SecurityFinding{
		OrgID: "org", DiscoveryID: "d1", Source: "certificate",
		FindingType: "tls-certificate-expiring", Title: "TLS certificate expires soon: www.example.com",
		Severity: shared.SeverityMedium, Description: "in 20 days", Status: shared.FindingStatusOpen, ScanID: &scan1,
	}
	if err := s.upsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}
	finding.Severity, finding.Description, finding.ScanID = shared.SeverityHigh, "in 5 days", &scan2
	if err := s.upsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}

	coll := db.Collection(shared.CollectionFindings)
	if n, _ := coll.CountDocuments(ctx, bson.M{}); n != 1 {
		t.Fatalf("findings = %d, want 1", n)
	}
	var doc struct {
		Severity    string   `bson:"severity"`
		Description string   `bson:"description"`
		ScanIDs     []string `bson:"scan_ids"`
	}
	if err := coll.FindOne(ctx, bson.M{}).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc.Severity != shared.SeverityHigh || doc.Description != "in 5 days" || len(doc.ScanIDs) != 2 {
		t.Fatalf("finding = %+v, want high, the new description and both scans", doc)
	}
}
