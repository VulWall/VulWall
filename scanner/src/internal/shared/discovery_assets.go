package shared

import (
	"context"
	"slices"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// NewDiscoveryAssetIDs is the asset_ids of a discovery that the scan of assetID creates:
// nil without an asset, so the insert holds no empty id.
func NewDiscoveryAssetIDs(assetID string) []string {
	if assetID == "" {
		return nil
	}
	return []string{assetID}
}

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

// AddIPAssetID adds assetID to the IP discovery and then to every port of that IP (of any
// scan: a port closed now still belongs to the asset). The order matters: port ingestion
// copies the IP's list onto a port after writing it, so a port written while this runs gets
// the id one way or the other.
func AddIPAssetID(ctx context.Context, db *mongo.Database, orgID, ipDiscoveryID, ip, assetID string) error {
	if err := AddDiscoveryAssetIDs(ctx, db, bson.M{"_id": ipDiscoveryID, "org_id": orgID}, assetID); err != nil {
		return err
	}
	return AddDiscoveryAssetIDs(ctx, db, bson.M{"org_id": orgID, "asset_type": AssetTypePort, "ip": ip}, assetID)
}
