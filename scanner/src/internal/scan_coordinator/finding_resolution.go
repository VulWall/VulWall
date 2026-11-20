package scan_coordinator

import (
	"context"
	"slices"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Resolution reasons, stored in findings.resolution_reason.
const (
	// ResolutionNotReproduced: the scan saw the finding's host live, the scanner that
	// reported the finding completed on it, and did not report the finding again.
	ResolutionNotReproduced = "not_reproduced"
	// ResolutionHostNoLongerFound: the finding's host was confirmed gone in goneAfterScans
	// consecutive drained scans.
	ResolutionHostNoLongerFound = "host_no_longer_found"
)

// goneAfterScans is how many consecutive pipeline_quiescent scans must confirm a host gone
// before its findings are resolved as host_no_longer_found.
const goneAfterScans = 3

// findingRef is the part of a finding that resolution needs.
type findingRef struct {
	ID          string `bson:"_id"`
	DiscoveryID string `bson:"discovery_id"`
	Source      string `bson:"source"`
	FindingType string `bson:"finding_type"`
	Title       string `bson:"title"`
}

// discoveryRef is the part of a discovery that resolution needs.
type discoveryRef struct {
	ID        string `bson:"_id"`
	AssetType string `bson:"asset_type"`
	IP        string `bson:"ip"`
	// Observed: the discovery has the closing scan in scan_ids (re-discovered live).
	Observed bool `bson:"observed"`
	// SeenIn: the recent scans (resolutionInput.recentScans) that have it in scan_ids.
	SeenIn []string `bson:"seen_in"`
}

// coverageRef is one scan_coverage record.
type coverageRef struct {
	ScanID      string              `bson:"scan_id"`
	Source      string              `bson:"source"`
	DiscoveryID string              `bson:"discovery_id"`
	Status      string              `bson:"status"`
	Reported    []shared.FindingKey `bson:"reported"`
}

// coverageKey identifies a coverage record within one scan.
type coverageKey struct{ source, discoveryID string }

// resolutionInput is everything the resolution decision reads, loaded by loadResolutionInput.
type resolutionInput struct {
	orgID string
	// recentScans are the closing scan followed by the org's previous pipeline_quiescent
	// scans, newest first, at most goneAfterScans in all.
	recentScans []string
	candidates  []findingRef
	discoveries map[string]discoveryRef
	// coverage of the closing scan, by (source, discovery_id).
	coverage map[coverageKey]coverageRef
	// hostChecks holds, per recent scan, the domain_discovery "absent" and the
	// port_discovery "ok" records of that scan.
	hostChecks map[string]map[coverageKey]bool
}

// resolutionDecision is the outcome for the candidates of one scan.
type resolutionDecision struct {
	notReproduced []string
	gone          []string
	unchecked     []string
}

// decideResolutions resolves a finding only on positive evidence from the closing scan:
//
//   - not_reproduced: its discovery was re-discovered live in this scan, the scanner that
//     produced it (finding.source) completed on that discovery (coverage ok), and the
//     scanner did not report it again (its key is not in the coverage's reported list);
//   - host_no_longer_found: its host was confirmed gone in each of the last goneAfterScans
//     drained scans, this one included (hostGone).
//
// Every other candidate stays open (unchecked): a missing coverage record, a check that did
// not complete, a host that was not seen this scan, a disabled asset or a lost message all
// leave the finding as it was. Absence of data never resolves anything.
func decideResolutions(in resolutionInput) resolutionDecision {
	var out resolutionDecision
	for _, f := range in.candidates {
		d, ok := in.discoveries[f.DiscoveryID]
		switch {
		case !ok:
			out.unchecked = append(out.unchecked, f.ID)
		case d.Observed && notReproduced(f, in.coverage[coverageKey{f.Source, f.DiscoveryID}]):
			out.notReproduced = append(out.notReproduced, f.ID)
		case hostGone(in, d):
			out.gone = append(out.gone, f.ID)
		default:
			out.unchecked = append(out.unchecked, f.ID)
		}
	}
	return out
}

// notReproduced reports whether cov proves that f is no longer present: the check completed
// and did not report f.
func notReproduced(f findingRef, cov coverageRef) bool {
	if cov.Status != shared.CoverageOK {
		return false // no record, or the check did not complete
	}
	for _, k := range cov.Reported {
		if k.FindingType == f.FindingType && k.Title == f.Title {
			return false
		}
	}
	return true
}

// hostGone reports whether d was confirmed gone in each of the last goneAfterScans drained
// scans. A domain or subdomain is gone in a scan when domain discovery reported it absent (the
// local and the public resolvers agree it has no address). A port is gone in a scan when the
// port scan of its IP completed and did not find it open. Other types are never gone.
func hostGone(in resolutionInput, d discoveryRef) bool {
	if len(in.recentScans) < goneAfterScans {
		return false
	}
	var key coverageKey
	switch d.AssetType {
	case shared.AssetTypeDomain, shared.AssetTypeSubdomain:
		key = coverageKey{shared.CoverageSourceDomainDiscovery, d.ID}
	case shared.AssetTypePort:
		if d.IP == "" {
			return false
		}
		key = coverageKey{shared.CoverageSourcePortDiscovery, shared.GenerateIPID(in.orgID, d.IP)}
	default:
		return false
	}
	for _, scanID := range in.recentScans[:goneAfterScans] {
		if !in.hostChecks[scanID][key] {
			return false
		}
		if d.AssetType == shared.AssetTypePort && slices.Contains(d.SeenIn, scanID) {
			return false // the port was open in that scan
		}
	}
	return true
}

// findingsToResolve loads the evidence of the closing scan and decides which open findings
// it resolves. The candidates are every open finding of the org that this scan did not see,
// not only the ones the previous scan saw: a finding that one scan could not check is
// resolved by the first later scan that has the evidence.
func (m *ScanMonitor) findingsToResolve(ctx context.Context, scan shared.Scan) (resolutionDecision, error) {
	in, err := m.loadResolutionInput(ctx, scan)
	if err != nil || len(in.candidates) == 0 {
		return resolutionDecision{}, err
	}
	return decideResolutions(in), nil
}

func (m *ScanMonitor) loadResolutionInput(ctx context.Context, scan shared.Scan) (resolutionInput, error) {
	in := resolutionInput{orgID: scan.OrgID}

	cursor, err := m.db.Collection(shared.CollectionFindings).Find(ctx,
		bson.M{"org_id": scan.OrgID, "status": shared.FindingStatusOpen, "scan_ids": bson.M{"$ne": scan.ID}},
		options.Find().SetProjection(bson.M{"discovery_id": 1, "source": 1, "finding_type": 1, "title": 1}),
	)
	if err != nil {
		return in, err
	}
	if err := cursor.All(ctx, &in.candidates); err != nil || len(in.candidates) == 0 {
		return in, err
	}

	if in.recentScans, err = m.recentQuiescentScans(ctx, scan); err != nil {
		return in, err
	}
	if in.discoveries, err = m.discoveriesOf(ctx, scan.OrgID, scan.ID, in.recentScans, in.candidates); err != nil {
		return in, err
	}

	cursor, err = m.db.Collection(shared.CollectionScanCoverage).Find(ctx,
		bson.M{"scan_id": bson.M{"$in": in.recentScans}, "org_id": scan.OrgID})
	if err != nil {
		return in, err
	}
	var records []coverageRef
	if err := cursor.All(ctx, &records); err != nil {
		return in, err
	}
	in.coverage = map[coverageKey]coverageRef{}
	in.hostChecks = map[string]map[coverageKey]bool{}
	for _, r := range records {
		key := coverageKey{r.Source, r.DiscoveryID}
		if r.ScanID == scan.ID {
			in.coverage[key] = r
		}
		hostCheck := (r.Source == shared.CoverageSourceDomainDiscovery && r.Status == shared.CoverageAbsent) ||
			(r.Source == shared.CoverageSourcePortDiscovery && r.Status == shared.CoverageOK)
		if hostCheck {
			if in.hostChecks[r.ScanID] == nil {
				in.hostChecks[r.ScanID] = map[coverageKey]bool{}
			}
			in.hostChecks[r.ScanID][key] = true
		}
	}
	return in, nil
}

// recentQuiescentScans returns the closing scan followed by the org's previous scans that
// closed pipeline_quiescent, newest first, goneAfterScans in all at most. A scan closed by a
// timeout or a restart did not see its pipeline drain, so it confirms nothing.
func (m *ScanMonitor) recentQuiescentScans(ctx context.Context, scan shared.Scan) ([]string, error) {
	cursor, err := m.db.Collection(shared.CollectionScans).Find(ctx,
		bson.M{
			"org_id":            scan.OrgID,
			"_id":               bson.M{"$ne": scan.ID},
			"status":            shared.StatusDone,
			"completion_reason": shared.ScanCompletionPipelineQuiescent,
			"created_at":        bson.M{"$lt": scan.CreatedAt},
		},
		options.Find().
			SetProjection(bson.M{"_id": 1}).
			SetSort(bson.D{{Key: "created_at", Value: -1}}).
			SetLimit(goneAfterScans-1),
	)
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ID string `bson:"_id"`
	}
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}
	ids := []string{scan.ID}
	for _, d := range docs {
		ids = append(ids, d.ID)
	}
	return ids, nil
}

// discoveriesOf loads the discoveries the findings are attached to, keyed by id, with
// whether the closing scan observed each one and which recent scans saw it.
func (m *ScanMonitor) discoveriesOf(ctx context.Context, orgID, scanID string, recent []string, findings []findingRef) (map[string]discoveryRef, error) {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.DiscoveryID)
	}
	scanIDs := bson.M{"$ifNull": bson.A{"$scan_ids", bson.A{}}}
	cursor, err := m.db.Collection(shared.CollectionDiscoveries).Find(ctx,
		bson.M{"org_id": orgID, "_id": bson.M{"$in": ids}},
		options.Find().SetProjection(bson.M{
			"asset_type": 1,
			"ip":         1,
			"observed":   bson.M{"$in": bson.A{scanID, scanIDs}},
			"seen_in":    bson.M{"$setIntersection": bson.A{scanIDs, recent}},
		}),
	)
	if err != nil {
		return nil, err
	}
	var docs []discoveryRef
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}
	byID := make(map[string]discoveryRef, len(docs))
	for _, d := range docs {
		byID[d.ID] = d
	}
	return byID, nil
}

// resolveFindings marks the findings resolved with reason. Status and scan_ids are checked
// again: a late ingestion write may have seen a finding since the decision.
func (m *ScanMonitor) resolveFindings(ctx context.Context, scan shared.Scan, ids []string, reason string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := m.db.Collection(shared.CollectionFindings).UpdateMany(ctx,
		bson.M{
			"_id":      bson.M{"$in": ids},
			"org_id":   scan.OrgID,
			"status":   shared.FindingStatusOpen,
			"scan_ids": bson.M{"$ne": scan.ID},
		},
		bson.M{"$set": bson.M{
			"status":              shared.FindingStatusResolved,
			"resolved_at":         time.Now(),
			"resolved_by_scan_id": scan.ID,
			"resolution_reason":   reason,
		}},
	)
	if err != nil {
		return 0, err
	}
	return res.ModifiedCount, nil
}
