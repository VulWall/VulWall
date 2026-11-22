package findings_ingestion

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/domain_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

const lateOrg = "org"

// lateEnv is a findings ingestion service on a throwaway database with the org lateOrg and
// these discoveries of it: "d-legacy" without asset_ids (recorded before ownership),
// "d-owned" owned by an asset, and "d-deleting" with asset_ids: [] (an asset delete is
// pending). "d-other" exists only in another org. "d-deleted" exists nowhere.
func lateEnv(t *testing.T) (*Service, *mongo.Database) {
	t.Helper()
	db := testMongo(t)
	ctx := context.Background()
	if _, err := db.Collection(shared.CollectionOrganizations).InsertOne(ctx, bson.M{"_id": lateOrg}); err != nil {
		t.Fatal(err)
	}
	docs := []any{
		bson.M{"_id": "d-legacy", "org_id": lateOrg, "asset_type": shared.AssetTypeSubdomain},
		bson.M{"_id": "d-owned", "org_id": lateOrg, "asset_type": shared.AssetTypeSubdomain, "asset_ids": bson.A{"asset-a"}},
		bson.M{"_id": "d-deleting", "org_id": lateOrg, "asset_type": shared.AssetTypeSubdomain, "asset_ids": bson.A{}},
		bson.M{"_id": "d-other", "org_id": "other-org", "asset_type": shared.AssetTypeSubdomain, "asset_ids": bson.A{"asset-x"}},
	}
	if _, err := db.Collection(shared.CollectionDiscoveries).InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	logger := zap.NewNop()
	// No Redis: the findings below are low severity, so no knowledge-base job is published.
	return NewService(db, nil, logger, shared.NewOrgGuard(db, logger)), db
}

func lowFinding(discoveryID string) shared.SecurityFinding {
	scanID := "scan-1"
	return shared.SecurityFinding{
		OrgID: lateOrg, DiscoveryID: discoveryID, Source: "nuclei", FindingType: "tech-detect",
		Title: "Some finding", Severity: shared.SeverityLow, Status: shared.FindingStatusOpen, ScanID: &scanID,
	}
}

// TestLateFindingOfDeletedDiscoveryIsDropped (#131): a finding that arrives after an asset
// delete removed its discovery, or while the delete is pending, is not written. A finding of an
// existing discovery is written as before.
func TestLateFindingOfDeletedDiscoveryIsDropped(t *testing.T) {
	s, db := lateEnv(t)
	ctx := context.Background()
	cases := []struct {
		discoveryID string
		written     bool
	}{
		{"d-deleted", false},  // the delete removed the discovery
		{"d-deleting", false}, // asset_ids: [], the delete is pending
		{"d-other", false},    // the id exists, but in another org
		{"", false},           // no discovery at all
		{"d-legacy", true},    // no asset_ids field: visible, not recorded
		{"d-owned", true},
	}
	for _, c := range cases {
		if err := s.ProcessFinding(ctx, lowFinding(c.discoveryID)); err != nil {
			t.Fatalf("%q: %v", c.discoveryID, err)
		}
		n, err := db.Collection(shared.CollectionFindings).CountDocuments(ctx,
			bson.M{"org_id": lateOrg, "discovery_id": c.discoveryID})
		if err != nil {
			t.Fatal(err)
		}
		if got := n == 1; got != c.written {
			t.Errorf("finding of %q written = %v, want %v", c.discoveryID, got, c.written)
		}
	}
}

// TestLateCoverageOfDeletedDiscoveryIsDropped (#131): a scanner's coverage for a missing or
// delete-pending discovery is not written. Domain and port discovery coverage can arrive before
// its discovery is written (first scan), so it is kept when the discovery is missing, and
// dropped only while a delete is pending.
func TestLateCoverageOfDeletedDiscoveryIsDropped(t *testing.T) {
	s, db := lateEnv(t)
	ctx := context.Background()
	scanID := "scan-1"
	cases := []struct {
		source, discoveryID, status string
		written                     bool
	}{
		{"nuclei", "d-deleted", shared.CoverageOK, false},
		{"nuclei", "d-deleting", shared.CoverageOK, false},
		{"nuclei", "d-other", shared.CoverageOK, false},
		{"nuclei", "d-legacy", shared.CoverageOK, true},
		{"nuclei", "d-owned", shared.CoverageOK, true},
		{shared.CoverageSourceDomainDiscovery, "d-new-root", shared.CoverageAbsent, true},
		{shared.CoverageSourcePortDiscovery, "d-new-ip", shared.CoverageOK, true},
		{shared.CoverageSourceDomainDiscovery, "d-deleting", shared.CoverageAbsent, false},
		{shared.CoverageSourcePortDiscovery, "d-deleting", shared.CoverageOK, false},
	}
	for _, c := range cases {
		msg := shared.CoverageMessage(lateOrg, &scanID, "trace", shared.ScanCoverage{
			Source: c.source, DiscoveryID: c.discoveryID, Target: "t", Status: c.status,
		})
		if err := s.RecordCoverage(ctx, msg); err != nil {
			t.Fatalf("%s/%s: %v", c.source, c.discoveryID, err)
		}
		n, err := db.Collection(shared.CollectionScanCoverage).CountDocuments(ctx,
			bson.M{"scan_id": scanID, "source": c.source, "discovery_id": c.discoveryID})
		if err != nil {
			t.Fatal(err)
		}
		if got := n == 1; got != c.written {
			t.Errorf("coverage %s/%s written = %v, want %v", c.source, c.discoveryID, got, c.written)
		}
	}
}

// TestFindingOfNewDiscoveryIsWritten: in the normal flow domain ingestion writes a new
// discovery and then triggers the scanners; a finding a scanner reports for that trigger is
// written.
func TestFindingOfNewDiscoveryIsWritten(t *testing.T) {
	s, db := lateEnv(t)
	redisURI := os.Getenv("VULWALL_TEST_REDIS_URI")
	if redisURI == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	ctx := context.Background()
	opts, err := redis.ParseURL(redisURI)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	streams := []string{shared.StreamIPDiscoveryQueue, shared.StreamDiscoveryEnrichmentQueue, shared.StreamDomainScanTriggers}
	rdb.Del(ctx, streams...)
	t.Cleanup(func() {
		rdb.Del(ctx, streams...)
		_ = rdb.Close()
	})
	if _, err := db.Collection(shared.CollectionAssets).InsertOne(ctx, bson.M{"_id": "asset-a", "org_id": lateOrg, "enabled": true}); err != nil {
		t.Fatal(err)
	}

	logger := zap.NewNop()
	domain := domain_ingestion.NewService(db, rdb, logger, shared.NewOrgGuard(db, logger), shared.NewAssetGuard(db, logger))
	scanID, ip := "scan-1", "203.0.113.10"
	host := "new.a.test"
	if err := domain.ProcessFinding(ctx, shared.DiscoveryFinding{
		DiscoveryID: shared.GenerateDomainID(lateOrg, host), AssetType: shared.AssetTypeDomain,
		TraceID: "trace", ScanID: &scanID, OrgID: lateOrg, AssetID: "asset-a", Source: "subfinder",
		Host: host, IP: &ip, Status: shared.AssetStatusActive, Timestamp: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// The scanner gets the discovery id from the trigger.
	msgs, err := rdb.XRange(ctx, shared.StreamDomainScanTriggers, "-", "+").Result()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("domain scan triggers = %d (%v), want 1", len(msgs), err)
	}
	var trigger shared.DiscoveryFinding
	if err := json.Unmarshal([]byte(msgs[0].Values["data"].(string)), &trigger); err != nil {
		t.Fatal(err)
	}

	if err := s.ProcessFinding(ctx, lowFinding(trigger.DiscoveryID)); err != nil {
		t.Fatal(err)
	}
	n, err := db.Collection(shared.CollectionFindings).CountDocuments(ctx,
		bson.M{"org_id": lateOrg, "discovery_id": trigger.DiscoveryID})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("findings of the new discovery = %d, want 1", n)
	}
}
