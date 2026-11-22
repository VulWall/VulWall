package shared

import (
	"context"
	"slices"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// AddDiscoveryAssetIDs adds assetIDs to asset_ids of the discoveries that match filter:
// the assets whose scans reached them. It is $addToSet, so a repeat adds nothing. Empty ids
// are skipped, and with none left it writes nothing. The filter must hold org_id.
func AddDiscoveryAssetIDs(ctx context.Context, db *mongo.Database, filter bson.M, assetIDs ...string) error {
	ids := slices.DeleteFunc(slices.Clone(assetIDs), func(id string) bool { return id == "" })
	if len(ids) == 0 {
		return nil
	}
	_, err := db.Collection(CollectionDiscoveries).UpdateMany(ctx, filter,
		bson.M{"$addToSet": bson.M{"asset_ids": bson.M{"$each": ids}}})
	return err
}
