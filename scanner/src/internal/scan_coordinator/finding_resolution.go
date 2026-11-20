package scan_coordinator

import (
	"context"
	"regexp"
	"strings"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// findingRef is the part of a finding that resolution needs.
type findingRef struct {
	ID          string `bson:"_id"`
	DiscoveryID string `bson:"discovery_id"`
}

// discoveryRef is the part of a discovery that maps a finding to a root domain.
type discoveryRef struct {
	ID        string `bson:"_id"`
	AssetType string `bson:"asset_type"`
	Domain    string `bson:"domain"`
	Subdomain string `bson:"subdomain"`
	IP        string `bson:"ip"`
}

// findingsToResolve returns the findings a reconciling close of scan resolves, and the ones it
// leaves open because they are under a degraded asset (unchecked).
//
// The candidates are every open finding of the org that this scan did not see, not only the
// ones the previous scan saw: a finding that a partial scan could not check is then still
// resolved by the first later scan that checks its asset, and an org whose every scan has one
// degraded asset (an expired domain) still resolves the findings of its other assets.
func (m *ScanMonitor) findingsToResolve(ctx context.Context, scan shared.Scan) (resolve, unchecked []string, err error) {
	candidates, err := m.openFindingsNotSeen(ctx, scan.OrgID, scan.ID)
	if err != nil || len(candidates) == 0 {
		return nil, nil, err
	}

	domains := degradedDomains(scan.DegradedAssets)
	if len(domains) == 0 {
		for _, f := range candidates {
			resolve = append(resolve, f.ID)
		}
		return resolve, nil, nil
	}

	discoveries, err := m.discoveriesOf(ctx, scan.OrgID, candidates)
	if err != nil {
		return nil, nil, err
	}
	ips, err := m.ipsUnderDomains(ctx, scan.OrgID, domains)
	if err != nil {
		return nil, nil, err
	}
	resolve, unchecked = partitionByDegraded(candidates, discoveries, domains, ips)
	return resolve, unchecked, nil
}

// partitionByDegraded splits candidate findings into those that may be resolved and those
// under a degraded root domain, which stay open. A finding is under a degraded root when its
// discovery is that domain or a name below it, or an IP or port at an address that any name
// below a degraded root has resolved to (ips). IP discoveries are shared per org, so an IP
// that a healthy root also uses stays open too. A finding whose discovery is missing or of an
// unknown type cannot be mapped and stays open.
func partitionByDegraded(candidates []findingRef, discoveries map[string]discoveryRef, domains []string, ips map[string]bool) (resolve, unchecked []string) {
	for _, f := range candidates {
		if d, ok := discoveries[f.DiscoveryID]; !ok || underDegraded(d, domains, ips) {
			unchecked = append(unchecked, f.ID)
		} else {
			resolve = append(resolve, f.ID)
		}
	}
	return resolve, unchecked
}

func underDegraded(d discoveryRef, domains []string, ips map[string]bool) bool {
	switch d.AssetType {
	case shared.AssetTypeDomain:
		return d.Domain == "" || hostUnder(d.Domain, domains)
	case shared.AssetTypeSubdomain:
		return d.Subdomain == "" || hostUnder(d.Subdomain, domains)
	case shared.AssetTypeIP, shared.AssetTypePort:
		return d.IP == "" || ips[d.IP]
	}
	return true
}

// hostUnder reports whether host is one of domains or a name below one of them.
func hostUnder(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// degradedDomains returns the distinct, lower-cased domains of the degraded assets.
func degradedDomains(assets []shared.DegradedAsset) []string {
	seen := map[string]bool{}
	var domains []string
	for _, a := range assets {
		d := strings.ToLower(strings.TrimSuffix(a.Domain, "."))
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	return domains
}

// openFindingsNotSeen returns the org's open findings whose scan_ids do not include scanID.
func (m *ScanMonitor) openFindingsNotSeen(ctx context.Context, orgID, scanID string) ([]findingRef, error) {
	cursor, err := m.db.Collection(shared.CollectionFindings).Find(ctx,
		bson.M{"org_id": orgID, "status": shared.FindingStatusOpen, "scan_ids": bson.M{"$ne": scanID}},
		options.Find().SetProjection(bson.M{"_id": 1, "discovery_id": 1}),
	)
	if err != nil {
		return nil, err
	}
	var refs []findingRef
	err = cursor.All(ctx, &refs)
	return refs, err
}

// discoveriesOf loads the discoveries the findings are attached to, keyed by id.
func (m *ScanMonitor) discoveriesOf(ctx context.Context, orgID string, findings []findingRef) (map[string]discoveryRef, error) {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.DiscoveryID)
	}
	cursor, err := m.db.Collection(shared.CollectionDiscoveries).Find(ctx,
		bson.M{"org_id": orgID, "_id": bson.M{"$in": ids}},
		options.Find().SetProjection(bson.M{"asset_type": 1, "domain": 1, "subdomain": 1, "ip": 1}),
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

// ipsUnderDomains returns every address that the domains, or any name below them, has ever
// resolved to (resolution_history, closed entries included).
func (m *ScanMonitor) ipsUnderDomains(ctx context.Context, orgID string, domains []string) (map[string]bool, error) {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = regexp.QuoteMeta(d)
	}
	below := primitive.Regex{Pattern: `\.(?:` + strings.Join(quoted, "|") + `)$`, Options: "i"}
	cursor, err := m.db.Collection(shared.CollectionDiscoveries).Find(ctx,
		bson.M{
			"org_id":     orgID,
			"asset_type": bson.M{"$in": []string{shared.AssetTypeDomain, shared.AssetTypeSubdomain}},
			"$or": bson.A{
				bson.M{"domain": bson.M{"$in": domains}},
				bson.M{"subdomain": bson.M{"$in": domains}},
				bson.M{"subdomain": below},
			},
		},
		options.Find().SetProjection(bson.M{"resolution_history.ip": 1}),
	)
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ResolutionHistory []struct {
			IP string `bson:"ip"`
		} `bson:"resolution_history"`
	}
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}
	ips := map[string]bool{}
	for _, d := range docs {
		for _, r := range d.ResolutionHistory {
			ips[r.IP] = true
		}
	}
	return ips, nil
}
