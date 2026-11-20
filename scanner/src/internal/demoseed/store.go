package demoseed

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/sysinfo"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	collSuppressions = "finding_suppressions" // web app only
	// collState keeps, per seeded organization, the values Apply replaced. It is a collection
	// of its own because the web app saves an organization with a full replace, which drops
	// fields it does not know.
	collState      = "demo_seed"
	demoField      = "demo"
	defaultOrgName = "My Organization"
)

// orgFields are the organization fields Apply changes and Reset restores.
var orgFields = []string{"company_name", "industry", "website", "scan_settings", "tour_completed"}

// demoCollections hold only documents that Apply inserted (demo: true); Reset deletes those.
var demoCollections = []string{
	shared.CollectionAssets, shared.CollectionDiscoveries, shared.CollectionFindings, shared.CollectionScans,
	shared.CollectionScanCoverage, collSuppressions, sysinfo.Collection,
}

// ErrHasData means the organization already has assets or findings that are not sample data.
var ErrHasData = errors.New("the organization already has assets or findings")

// Options configure Apply.
type Options struct {
	Force   bool      // seed even when the organization has its own assets or findings
	Now     time.Time // the scans end a few days before Now
	Version string    // scanner version for system_info (only written when the document is missing)
}

// Apply seeds the sample data into the organization the web app uses (the oldest one; one is
// created as the web app would when there is none). Sample data from an earlier run is
// replaced. Without Force it refuses when the organization has assets or findings of its own.
func Apply(ctx context.Context, db *mongo.Database, opt Options) (*Dataset, error) {
	org, err := ensureOrganization(ctx, db, opt.Now)
	if err != nil {
		return nil, err
	}
	orgID, err := orgIDOf(org)
	if err != nil {
		return nil, err
	}

	notDemo := bson.M{"org_id": orgID, demoField: bson.M{"$ne": true}}
	for _, coll := range []string{shared.CollectionAssets, shared.CollectionFindings} {
		n, err := db.Collection(coll).CountDocuments(ctx, notDemo)
		if err != nil {
			return nil, fmt.Errorf("count %s: %w", coll, err)
		}
		if n > 0 && !opt.Force {
			return nil, fmt.Errorf("%w (%d in %s); use --force to add the sample data anyway", ErrHasData, n, coll)
		}
	}

	if err := deleteDemoDocs(ctx, db, nil); err != nil {
		return nil, err
	}
	ds := Build(orgID, opt.Now, opt.Version)
	if err := updateOrganization(ctx, db, org, ds); err != nil {
		return nil, err
	}
	writes := []struct {
		coll string
		docs []any
	}{
		{shared.CollectionAssets, toAny(ds.Assets)},
		{shared.CollectionDiscoveries, toAny(ds.Discoveries)},
		{shared.CollectionFindings, toAny(ds.Findings)},
		{shared.CollectionScans, toAny(ds.Scans)},
		{shared.CollectionScanCoverage, toAny(ds.Coverage)},
		{collSuppressions, toAny(ds.Suppressions)},
	}
	for _, w := range writes {
		if _, err := db.Collection(w.coll).InsertMany(ctx, w.docs); err != nil {
			return nil, fmt.Errorf("insert %s: %w", w.coll, err)
		}
	}
	// A running scanner owns system_info; only fill it in when it has never run.
	info, err := toMap(ds.SystemInfo)
	if err != nil {
		return nil, err
	}
	delete(info, "_id") // from the filter
	_, err = db.Collection(sysinfo.Collection).UpdateOne(ctx, bson.M{"_id": sysinfo.DocID},
		bson.M{"$setOnInsert": info}, options.Update().SetUpsert(true))
	if err != nil {
		return nil, fmt.Errorf("write system_info: %w", err)
	}
	return ds, nil
}

// ResetResult counts what Reset removed.
type ResetResult struct {
	Deleted      map[string]int64
	OrgsRestored int64
}

// Reset deletes every sample document (demo: true) and gives the organization back its own
// name, schedule and tour state. Documents without the mark are not touched.
func Reset(ctx context.Context, db *mongo.Database) (*ResetResult, error) {
	res := &ResetResult{Deleted: map[string]int64{}}
	if err := deleteDemoDocs(ctx, db, res.Deleted); err != nil {
		return nil, err
	}
	cur, err := db.Collection(collState).Find(ctx, bson.M{})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", collState, err)
	}
	var states []struct {
		ID       any    `bson:"_id"`
		Original bson.M `bson:"original"`
	}
	if err := cur.All(ctx, &states); err != nil {
		return nil, fmt.Errorf("read %s: %w", collState, err)
	}
	for _, st := range states {
		set, unset := bson.M{"updated_at": time.Now().UTC()}, bson.M{}
		for _, f := range orgFields {
			if v, ok := st.Original[f]; ok {
				set[f] = v
			} else {
				unset[f] = ""
			}
		}
		update := bson.M{"$set": set}
		if len(unset) > 0 {
			update["$unset"] = unset
		}
		r, err := db.Collection(shared.CollectionOrganizations).UpdateOne(ctx, bson.M{"_id": st.ID}, update)
		if err != nil {
			return nil, fmt.Errorf("restore organization: %w", err)
		}
		res.OrgsRestored += r.MatchedCount
		if _, err := db.Collection(collState).DeleteOne(ctx, bson.M{"_id": st.ID}); err != nil {
			return nil, fmt.Errorf("delete %s: %w", collState, err)
		}
	}
	return res, nil
}

func deleteDemoDocs(ctx context.Context, db *mongo.Database, counts map[string]int64) error {
	for _, coll := range demoCollections {
		r, err := db.Collection(coll).DeleteMany(ctx, bson.M{demoField: true})
		if err != nil {
			return fmt.Errorf("delete demo %s: %w", coll, err)
		}
		if counts != nil {
			counts[coll] = r.DeletedCount
		}
	}
	return nil
}

// ensureOrganization returns the organization the web app resolves (the oldest by created_at),
// creating it as DefaultOrganization.EnsureExistsAsync does when there is none.
func ensureOrganization(ctx context.Context, db *mongo.Database, now time.Time) (bson.M, error) {
	coll := db.Collection(shared.CollectionOrganizations)
	var org bson.M
	err := coll.FindOne(ctx, bson.M{}, options.FindOne().SetSort(bson.D{{Key: "created_at", Value: 1}})).Decode(&org)
	if err == nil {
		return org, nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fmt.Errorf("read organization: %w", err)
	}
	org = bson.M{
		"_id": primitive.NewObjectID(), "company_name": defaultOrgName,
		"scan_settings": bson.M{"scan_cron": "0 2 * * 1", "enabled": true},
		"created_at":    now.UTC(), "updated_at": now.UTC(), "tour_completed": false,
	}
	if _, err := coll.InsertOne(ctx, org); err != nil {
		return nil, fmt.Errorf("create organization: %w", err)
	}
	return org, nil
}

func orgIDOf(org bson.M) (string, error) {
	switch id := org["_id"].(type) {
	case primitive.ObjectID:
		return id.Hex(), nil
	case string:
		return id, nil
	}
	return "", fmt.Errorf("organization _id has unexpected type %T", org["_id"])
}

// updateOrganization names the organization "Acme Demo", sets a weekly schedule on the day the
// sample scans ran and marks the tour done. The first run keeps the organization's own values
// in the demo_seed collection for Reset.
func updateOrganization(ctx context.Context, db *mongo.Database, org bson.M, ds *Dataset) error {
	original := bson.M{}
	for _, f := range orgFields {
		if v, ok := org[f]; ok {
			original[f] = v
		}
	}
	_, err := db.Collection(collState).UpdateOne(ctx, bson.M{"_id": org["_id"]},
		bson.M{"$setOnInsert": bson.M{"original": original, "seeded_at": time.Now().UTC()}}, options.Update().SetUpsert(true))
	if err != nil {
		return fmt.Errorf("save the organization's values: %w", err)
	}

	lastScheduled := ds.Scans[len(ds.Scans)-1].CreatedAt
	set := bson.M{
		"company_name":   CompanyName,
		"industry":       "Retail & e-commerce",
		"website":        "https://acme-demo.test",
		"scan_settings":  bson.M{"scan_cron": fmt.Sprintf("0 1 * * %d", int(lastScheduled.Weekday())), "enabled": true, "timezone": "Europe/Amsterdam"},
		"tour_completed": true,
		"updated_at":     time.Now().UTC(),
	}
	if _, err := db.Collection(shared.CollectionOrganizations).UpdateOne(ctx, bson.M{"_id": org["_id"]}, bson.M{"$set": set}); err != nil {
		return fmt.Errorf("update organization: %w", err)
	}
	return nil
}

func toMap(v any) (bson.M, error) {
	raw, err := bson.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m bson.M
	return m, bson.Unmarshal(raw, &m)
}

func toAny[T any](docs []T) []any {
	out := make([]any, len(docs))
	for i, d := range docs {
		out[i] = d
	}
	return out
}
