package port_ingestion

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
	"go.uber.org/zap"
)

// TestIPDiscoveryCDNEdgeMark checks against a real MongoDB (VULWALL_TEST_MONGO_URI) that an IP
// discovery of a CDN edge address carries metadata.cdn_edge, and that the mark goes away when
// the address is no longer in a CDN range.
func TestIPDiscoveryCDNEdgeMark(t *testing.T) {
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
	s := &Service{db: db, logger: zap.NewNop()}
	coll := db.Collection(shared.CollectionDiscoveries)
	mark := func(ip string) any {
		var doc struct {
			Metadata bson.M `bson:"metadata"`
		}
		if err := coll.FindOne(ctx, bson.M{"org_id": "org", "ip": ip}).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc.Metadata[shared.DiscoveryMetaCDNEdge]
	}

	// New Cloudflare address: marked; seen again: still marked.
	f := shared.IPDiscoveryFinding{OrgID: "org", IP: "104.20.23.154", Source: "port_discovery", Status: shared.AssetStatusActive}
	for range 2 {
		if _, _, err := s.ensureIPDiscovery(ctx, f, time.Now()); err != nil {
			t.Fatal(err)
		}
		if got := mark(f.IP); got != "Cloudflare" {
			t.Fatalf("cdn_edge = %v, want Cloudflare", got)
		}
	}

	// A customer server with a stale mark (its address left a CDN range): the mark goes.
	own := "203.0.113.10"
	if _, err := coll.InsertOne(ctx, bson.M{"_id": "ip-own", "org_id": "org", "asset_type": shared.AssetTypeIP, "ip": own,
		"metadata": bson.M{shared.DiscoveryMetaCDNEdge: "Fastly", "geo": bson.M{"country": "NL"}}}); err != nil {
		t.Fatal(err)
	}
	f.IP = own
	if _, _, err := s.ensureIPDiscovery(ctx, f, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := mark(own); got != nil {
		t.Fatalf("cdn_edge = %v, want it removed", got)
	}
}
