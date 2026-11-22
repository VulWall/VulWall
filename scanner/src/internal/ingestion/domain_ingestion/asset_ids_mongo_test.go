package domain_ingestion

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/port_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

const testOrg = "org"

// assetIDsEnv runs domain and port ingestion against a real MongoDB and Redis
// (VULWALL_TEST_MONGO_URI, VULWALL_TEST_REDIS_URI), as the ingestion workers do.
type assetIDsEnv struct {
	t      *testing.T
	ctx    context.Context
	domain *Service
	port   *port_ingestion.Service
	coll   *mongo.Collection
	rdb    *redis.Client
	scanID string
}

func newAssetIDsEnv(t *testing.T) *assetIDsEnv {
	mongoURI, redisURI := os.Getenv("VULWALL_TEST_MONGO_URI"), os.Getenv("VULWALL_TEST_REDIS_URI")
	if mongoURI == "" || redisURI == "" {
		t.Skip("VULWALL_TEST_MONGO_URI or VULWALL_TEST_REDIS_URI not set")
	}
	ctx := context.Background()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		t.Fatal(err)
	}
	db := client.Database("vulwall_test_" + uuid.NewString()[:8])
	opts, err := redis.ParseURL(redisURI)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	// The streams ingestion publishes to: start empty, and leave nothing for other tests.
	streams := []string{shared.StreamIPDiscoveryQueue, shared.StreamDiscoveryEnrichmentQueue,
		shared.StreamDomainScanTriggers, shared.StreamPortScanTriggers}
	rdb.Del(ctx, streams...)
	t.Cleanup(func() {
		rdb.Del(ctx, streams...)
		_ = rdb.Close()
		_ = db.Drop(ctx)
		_ = client.Disconnect(ctx)
	})
	if _, err := db.Collection(shared.CollectionOrganizations).InsertOne(ctx, bson.M{"_id": testOrg}); err != nil {
		t.Fatal(err)
	}
	logger := zap.NewNop()
	guard := shared.NewOrgGuard(db, logger)
	return &assetIDsEnv{
		t: t, ctx: ctx,
		domain: NewService(db, rdb, logger, guard),
		port:   port_ingestion.NewService(db, rdb, logger, guard),
		coll:   db.Collection(shared.CollectionDiscoveries),
		rdb:    rdb,
		scanID: "scan-1",
	}
}

// host ingests a domain discovery finding: a name that the scan of assetID reached,
// resolved to ip ("" = did not resolve).
func (e *assetIDsEnv) host(assetID, assetType, name, ip string) {
	e.t.Helper()
	f := shared.DiscoveryFinding{
		AssetType: assetType, TraceID: "trace", ScanID: &e.scanID, OrgID: testOrg, AssetID: assetID,
		Source: "subfinder", Host: name, Status: shared.AssetStatusActive, Timestamp: time.Now(),
	}
	if assetType == shared.AssetTypeDomain {
		f.DiscoveryID = shared.GenerateDomainID(testOrg, name)
	} else {
		f.DiscoveryID = shared.GenerateSubdomainID(testOrg, name)
		parent := shared.GenerateDomainID(testOrg, "a.test")
		f.ParentID = &parent
	}
	if ip != "" {
		f.IP = &ip
	}
	if err := e.domain.ProcessFinding(e.ctx, f); err != nil {
		e.t.Fatal(err)
	}
}

// openPort ingests a port finding of the port scan that the scan of assetID started.
func (e *assetIDsEnv) openPort(assetID, ip string, port int) {
	e.t.Helper()
	ipID := shared.GenerateIPID(testOrg, ip)
	f := shared.IPDiscoveryFinding{
		DiscoveryID: shared.GeneratePortID(testOrg, ip, port, shared.ProtocolTCP), AssetType: shared.AssetTypePort,
		TraceID: "trace", ScanID: &e.scanID, OrgID: testOrg, AssetID: assetID, Source: "port_discovery",
		ParentID: &ipID, IP: ip, Port: port, Protocol: shared.ProtocolTCP, Status: shared.AssetStatusActive,
		Timestamp: time.Now(),
	}
	if err := e.port.ProcessFinding(e.ctx, f); err != nil {
		e.t.Fatal(err)
	}
}

// assetIDs returns the discovery's asset_ids, and whether the field is there at all.
func (e *assetIDsEnv) assetIDs(id string) ([]string, bool) {
	e.t.Helper()
	var doc bson.M
	if err := e.coll.FindOne(e.ctx, bson.M{"_id": id}).Decode(&doc); err != nil {
		e.t.Fatalf("discovery %s: %v", id, err)
	}
	raw, ok := doc["asset_ids"]
	if !ok {
		return nil, false
	}
	var ids []string
	for _, v := range raw.(bson.A) {
		ids = append(ids, v.(string))
	}
	slices.Sort(ids)
	return ids, true
}

func (e *assetIDsEnv) wantAssetIDs(what, id string, want ...string) {
	e.t.Helper()
	got, _ := e.assetIDs(id)
	if !slices.Equal(got, want) {
		e.t.Errorf("%s: asset_ids = %v, want %v", what, got, want)
	}
}

// Two domain assets resolve to one IP in one scan. The IP is port-scanned once, for the
// first asset, so its port findings carry only that asset. The IP and its ports must still
// hold both assets, whichever comes first: the port finding or the second asset's IP write.
func TestAssetIDsOfSharedIPReachPorts(t *testing.T) {
	const ip = "203.0.113.7"
	for _, portFirst := range []bool{false, true} {
		name := "port after second asset"
		if portFirst {
			name = "port before second asset"
		}
		t.Run(name, func(t *testing.T) {
			e := newAssetIDsEnv(t)
			e.host("asset-a", shared.AssetTypeDomain, "a.test", ip)
			if portFirst {
				e.openPort("asset-a", ip, 443)
				e.host("asset-b", shared.AssetTypeDomain, "b.test", ip)
			} else {
				e.host("asset-b", shared.AssetTypeDomain, "b.test", ip)
				e.openPort("asset-a", ip, 443)
			}

			e.wantAssetIDs("a.test", shared.GenerateDomainID(testOrg, "a.test"), "asset-a")
			e.wantAssetIDs("b.test", shared.GenerateDomainID(testOrg, "b.test"), "asset-b")
			e.wantAssetIDs("IP", shared.GenerateIPID(testOrg, ip), "asset-a", "asset-b")
			e.wantAssetIDs("port 443", shared.GeneratePortID(testOrg, ip, 443, shared.ProtocolTCP), "asset-a", "asset-b")
		})
	}
}

// A subdomain found under a domain asset belongs to that asset.
func TestAssetIDsOfSubdomain(t *testing.T) {
	e := newAssetIDsEnv(t)
	e.host("asset-a", shared.AssetTypeDomain, "a.test", "203.0.113.8")
	e.host("asset-a", shared.AssetTypeSubdomain, "www.a.test", "203.0.113.9")

	// The port scan jobs carry the asset on to the port findings.
	msgs, err := e.rdb.XRange(e.ctx, shared.StreamIPDiscoveryQueue, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("%d port scan jobs, want one per IP", len(msgs))
	}
	for _, m := range msgs {
		var job shared.IPDiscoveryJob
		if err := json.Unmarshal([]byte(m.Values["data"].(string)), &job); err != nil {
			t.Fatal(err)
		}
		if job.AssetID != "asset-a" {
			t.Errorf("port scan job of %s: asset_id = %q, want asset-a", job.IP, job.AssetID)
		}
	}

	e.openPort("asset-a", "203.0.113.9", 80)

	e.wantAssetIDs("www.a.test", shared.GenerateSubdomainID(testOrg, "www.a.test"), "asset-a")
	e.wantAssetIDs("IP of www.a.test", shared.GenerateIPID(testOrg, "203.0.113.9"), "asset-a")
	e.wantAssetIDs("port 80", shared.GeneratePortID(testOrg, "203.0.113.9", 80, shared.ProtocolTCP), "asset-a")
}

// A finding without an asset adds nothing (no empty id in the list), and a later one that
// does not resolve still records its asset on the existing name.
func TestAssetIDsEmptyAndUnresolved(t *testing.T) {
	e := newAssetIDsEnv(t)
	const ip = "203.0.113.10"
	e.host("", shared.AssetTypeDomain, "a.test", ip)
	e.openPort("", ip, 22)
	for what, id := range map[string]string{
		"a.test":  shared.GenerateDomainID(testOrg, "a.test"),
		"IP":      shared.GenerateIPID(testOrg, ip),
		"port 22": shared.GeneratePortID(testOrg, ip, 22, shared.ProtocolTCP),
	} {
		if got, ok := e.assetIDs(id); ok {
			t.Errorf("%s: asset_ids = %v, want no field", what, got)
		}
	}

	e.host("asset-a", shared.AssetTypeDomain, "a.test", "")
	e.wantAssetIDs("a.test re-discovered without an IP", shared.GenerateDomainID(testOrg, "a.test"), "asset-a")
}

// A direct IP asset has no domain ingestion: port ingestion records it on the IP and ports.
func TestAssetIDsOfDirectIPAsset(t *testing.T) {
	e := newAssetIDsEnv(t)
	const ip = "203.0.113.11"
	e.openPort("asset-ip", ip, 22)
	e.openPort("asset-ip", ip, 443)

	e.wantAssetIDs("IP", shared.GenerateIPID(testOrg, ip), "asset-ip")
	e.wantAssetIDs("port 22", shared.GeneratePortID(testOrg, ip, 22, shared.ProtocolTCP), "asset-ip")
	e.wantAssetIDs("port 443", shared.GeneratePortID(testOrg, ip, 443, shared.ProtocolTCP), "asset-ip")
}
