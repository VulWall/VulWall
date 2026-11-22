package domain_ingestion

import (
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// A message of a scan still in flight when its asset was deleted (a scan closed by
// safety_timeout, a stuck consumer) must not write: it would create discoveries that hold
// only the dead id and stay hidden for good, or add the dead id to a shared discovery. The
// same holds once the delete has started (assets.deleting). The asset id is the hex of an
// ObjectID _id, as the scanner reads it from assets.
func TestLateMessageOfDeletedAssetWritesNothing(t *testing.T) {
	const ip = "203.0.113.9"
	for _, state := range []string{"deleted", "deleting"} {
		t.Run(state, func(t *testing.T) {
			e := newAssetIDsEnv(t)
			oid := primitive.NewObjectID()
			x := oid.Hex()
			assets := e.db.Collection(shared.CollectionAssets)
			if _, err := assets.InsertOne(e.ctx, bson.M{"_id": oid, "org_id": testOrg, "type": "domain", "enabled": true, "domain": "a.test"}); err != nil {
				t.Fatal(err)
			}
			e.host(x, shared.AssetTypeDomain, "a.test", ip)
			e.openPort(x, ip, 443)
			e.host("asset-b", shared.AssetTypeDomain, "b.test", ip)
			e.wantAssetIDs("shared IP before the delete", shared.GenerateIPID(testOrg, ip), x, "asset-b")

			// The web delete: mark (or remove) the asset, pull its id, delete what is left empty.
			if state == "deleted" {
				_, err := assets.DeleteOne(e.ctx, bson.M{"_id": oid})
				if err != nil {
					t.Fatal(err)
				}
			} else if _, err := assets.UpdateOne(e.ctx, bson.M{"_id": oid}, bson.M{"$set": bson.M{"enabled": false, "deleting": true}}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.coll.UpdateMany(e.ctx, bson.M{"org_id": testOrg, "asset_ids": x}, bson.M{"$pull": bson.M{"asset_ids": x}}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.coll.DeleteMany(e.ctx, bson.M{"org_id": testOrg, "asset_ids": bson.M{"$size": 0}}); err != nil {
				t.Fatal(err)
			}

			// Late messages of the old scan, seen by a worker whose cache holds no answer yet.
			e.restart()
			e.host(x, shared.AssetTypeDomain, "a.test", ip)
			e.host(x, shared.AssetTypeSubdomain, "late.a.test", ip)
			e.openPort(x, ip, 443)
			e.openPort(x, ip, 8443)
			e.directIP(x, ip)

			n, err := e.coll.CountDocuments(e.ctx, bson.M{"asset_ids": x})
			if err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%d discoveries hold the %s asset's id, want 0", n, state)
			}
			for what, id := range map[string]string{
				"a.test":      shared.GenerateDomainID(testOrg, "a.test"),
				"late.a.test": shared.GenerateSubdomainID(testOrg, "late.a.test"),
				"port 8443":   shared.GeneratePortID(testOrg, ip, 8443, shared.ProtocolTCP),
			} {
				if err := e.coll.FindOne(e.ctx, bson.M{"_id": id}).Err(); err != mongo.ErrNoDocuments {
					t.Errorf("%s: err = %v, want no document", what, err)
				}
			}
			e.wantAssetIDs("shared IP", shared.GenerateIPID(testOrg, ip), "asset-b")
			e.wantAssetIDs("shared port 443", shared.GeneratePortID(testOrg, ip, 443, shared.ProtocolTCP), "asset-b")

			// The live asset's results still go through.
			e.host("asset-b", shared.AssetTypeSubdomain, "www.b.test", ip)
			e.wantAssetIDs("www.b.test", shared.GenerateSubdomainID(testOrg, "www.b.test"), "asset-b")
		})
	}
}
