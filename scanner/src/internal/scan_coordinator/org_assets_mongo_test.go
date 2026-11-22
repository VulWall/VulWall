package scan_coordinator

import (
	"context"
	"os"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// A scan reads the enabled assets that no delete has started on: the web app sets deleting
// when a delete starts, and such an asset is never scanned again. An asset without the field
// is scanned. Set VULWALL_TEST_MONGO_URI to run it.
func TestOrgAssetsSkipsDeletingAssets(t *testing.T) {
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

	plain, notDeleting, deleting, disabled := primitive.NewObjectID(), primitive.NewObjectID(), primitive.NewObjectID(), primitive.NewObjectID()
	if _, err := db.Collection(shared.CollectionAssets).InsertMany(ctx, []any{
		bson.M{"_id": plain, "org_id": "org-1", "type": "domain", "enabled": true, "domain": "a.test"},
		bson.M{"_id": notDeleting, "org_id": "org-1", "type": "domain", "enabled": true, "domain": "b.test", "deleting": false},
		bson.M{"_id": deleting, "org_id": "org-1", "type": "domain", "enabled": true, "domain": "c.test", "deleting": true},
		bson.M{"_id": disabled, "org_id": "org-1", "type": "domain", "enabled": false, "domain": "d.test"},
	}); err != nil {
		t.Fatal(err)
	}

	assets, err := mongoScanStore{db: db}.orgAssets(ctx, "org-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ID] = true
	}
	if len(got) != 2 || !got[plain.Hex()] || !got[notDeleting.Hex()] {
		t.Errorf("orgAssets = %v, want only %s and %s", got, plain.Hex(), notDeleting.Hex())
	}
}
