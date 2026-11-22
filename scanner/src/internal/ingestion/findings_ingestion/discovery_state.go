package findings_ingestion

import (
	"context"
	"fmt"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// discoveryState is the state of the discovery that a finding or coverage message is for.
type discoveryState int

const (
	// discoveryPresent: the discovery exists in the org and no delete is pending on it.
	discoveryPresent discoveryState = iota
	// discoveryMissing: no discovery with that id exists in the org (an asset delete removed
	// it, or it was never written).
	discoveryMissing
	// discoveryDeleting: the discovery has asset_ids: [], which only the web app writes while
	// it deletes the discovery's last asset.
	discoveryDeleting
)

// discoveryStateOf looks up the discovery a message is for: one point read on _id, scoped to
// the org. A message of a scan that closed by safety_timeout (or sat behind a stuck consumer)
// can arrive after the user deleted the asset. The delete removes the discovery with its
// findings and coverage, so a write for it now would stay as an orphan (#131).
//
// No cache, unlike OrgGuard and AssetGuard: both negative states can change back (a later scan
// writes the discovery again under its deterministic id, or adds an owner to an empty
// asset_ids), so a cached "missing" would drop real results.
//
// Read from the primary: the discovery was written by another ingestion worker just before
// the scanner was triggered.
func (s *Service) discoveryStateOf(ctx context.Context, orgID, discoveryID string) (discoveryState, error) {
	if discoveryID == "" {
		return discoveryMissing, nil
	}
	var doc struct {
		// nil when the field is missing (not recorded); empty, not nil, for asset_ids: [].
		AssetIDs []string `bson:"asset_ids"`
	}
	err := s.db.Collection(shared.CollectionDiscoveries,
		options.Collection().SetReadPreference(readpref.Primary())).
		FindOne(ctx, bson.M{"_id": discoveryID, "org_id": orgID},
			options.FindOne().SetProjection(bson.M{"asset_ids": 1})).
		Decode(&doc)
	switch {
	case err == mongo.ErrNoDocuments:
		return discoveryMissing, nil
	case err != nil:
		// Not a reason to drop: the message is retried.
		return discoveryPresent, fmt.Errorf("failed to look up discovery %s: %w", discoveryID, err)
	case doc.AssetIDs != nil && len(doc.AssetIDs) == 0:
		return discoveryDeleting, nil
	}
	return discoveryPresent, nil
}

// coverageMayPrecedeDiscovery reports whether coverage of this source can arrive before its
// discovery is written. Domain and port discovery publish coverage on security_findings next to
// the discovery result they publish on their own results stream, and a different ingestion
// worker writes that discovery: an NXDOMAIN root's "absent" record and a direct IP asset's port
// scan "ok" record can both come first in the asset's first scan. Every other source is a
// scanner that ingestion triggers only after it wrote the discovery.
func coverageMayPrecedeDiscovery(source string) bool {
	return source == shared.CoverageSourceDomainDiscovery || source == shared.CoverageSourcePortDiscovery
}
