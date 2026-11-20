package scan_coordinator

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// TestFindingsToResolveAgainstMongo runs the loading queries (projection expressions included)
// against a real MongoDB. Set VULWALL_TEST_MONGO_URI to run it.
func TestFindingsToResolveAgainstMongo(t *testing.T) {
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

	now := time.Now()
	insert := func(coll string, docs ...any) {
		t.Helper()
		if _, err := db.Collection(coll).InsertMany(ctx, docs); err != nil {
			t.Fatal(err)
		}
	}
	insert(shared.CollectionScans,
		bson.M{"_id": "s1", "org_id": org, "status": shared.StatusDone, "completion_reason": shared.ScanCompletionPipelineQuiescent, "created_at": now.Add(-3 * time.Hour)},
		bson.M{"_id": "s-timeout", "org_id": org, "status": shared.StatusDone, "completion_reason": shared.ScanCompletionIdleTimeout, "created_at": now.Add(-150 * time.Minute)},
		bson.M{"_id": "s2", "org_id": org, "status": shared.StatusDone, "completion_reason": shared.ScanCompletionPipelineQuiescent, "created_at": now.Add(-2 * time.Hour)},
	)
	insert(shared.CollectionDiscoveries,
		bson.M{"_id": "live", "org_id": org, "asset_type": shared.AssetTypeSubdomain, "scan_ids": bson.A{"s1", "s2", thisScan}},
		bson.M{"_id": "gone", "org_id": org, "asset_type": shared.AssetTypeSubdomain, "scan_ids": bson.A{"s0"}},
		bson.M{"_id": "never", "org_id": org, "asset_type": shared.AssetTypeSubdomain},
	)
	insert(shared.CollectionFindings,
		bson.M{"_id": "f-fixed", "org_id": org, "discovery_id": "live", "source": "http-headers", "finding_type": "a", "title": "A", "status": "open", "scan_ids": bson.A{"s2"}},
		bson.M{"_id": "f-still", "org_id": org, "discovery_id": "live", "source": "http-headers", "finding_type": "b", "title": "B", "status": "open", "scan_ids": bson.A{"s2"}},
		bson.M{"_id": "f-nuclei", "org_id": org, "discovery_id": "live", "source": "nuclei", "finding_type": "c", "title": "C", "status": "open", "scan_ids": bson.A{"s2"}},
		bson.M{"_id": "f-gone", "org_id": org, "discovery_id": "gone", "source": "nuclei", "finding_type": "d", "title": "D", "status": "open", "scan_ids": bson.A{"s0"}},
		bson.M{"_id": "f-never", "org_id": org, "discovery_id": "never", "source": "nuclei", "finding_type": "e", "title": "E", "status": "open"},
		bson.M{"_id": "f-seen", "org_id": org, "discovery_id": "live", "source": "nuclei", "finding_type": "g", "title": "G", "status": "open", "scan_ids": bson.A{thisScan}},
	)
	absent := func(scan string) bson.M {
		return bson.M{"scan_id": scan, "org_id": org, "source": shared.CoverageSourceDomainDiscovery, "discovery_id": "gone", "status": shared.CoverageAbsent}
	}
	insert(shared.CollectionScanCoverage,
		bson.M{"scan_id": thisScan, "org_id": org, "source": "http-headers", "discovery_id": "live", "status": shared.CoverageOK,
			"reported": bson.A{bson.M{"finding_type": "b", "title": "B"}}},
		bson.M{"scan_id": thisScan, "org_id": org, "source": "nuclei", "discovery_id": "live", "status": shared.CoverageError},
		absent(thisScan), absent("s2"), absent("s1"),
	)

	m := &ScanMonitor{db: db, logger: zap.NewNop(), tracer: otel.Tracer("test")}
	scan := shared.Scan{ID: thisScan, OrgID: org, CreatedAt: now}
	d, err := m.findingsToResolve(ctx, scan)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(d.unchecked)
	if !slices.Equal(d.notReproduced, []string{"f-fixed"}) || !slices.Equal(d.gone, []string{"f-gone"}) ||
		!slices.Equal(d.unchecked, []string{"f-never", "f-nuclei", "f-still"}) {
		t.Fatalf("decision = %+v", d)
	}

	if n := m.resolve(ctx, scan, d); n != 2 {
		t.Fatalf("resolved %d, want 2", n)
	}
	var got struct {
		Status           string `bson:"status"`
		ResolutionReason string `bson:"resolution_reason"`
		ResolvedByScanID string `bson:"resolved_by_scan_id"`
	}
	if err := db.Collection(shared.CollectionFindings).FindOne(ctx, bson.M{"_id": "f-gone"}).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != shared.FindingStatusResolved || got.ResolutionReason != ResolutionHostNoLongerFound || got.ResolvedByScanID != thisScan {
		t.Fatalf("f-gone = %+v", got)
	}
}
