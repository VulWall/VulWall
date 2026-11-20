package demoseed

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/http_header_scanner/scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/core/sysinfo"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Resolution reasons and the coverage of a gone host, as the scan monitor writes them.
const reasonNotReproduced = "not_reproduced"

// Dataset is the sample data for one organization. Every document type carries Demo: true.
type Dataset struct {
	OrgID        string
	Assets       []assetDoc
	Discoveries  []discoveryDoc
	Findings     []findingDoc
	Scans        []scanDoc
	Coverage     []coverageDoc
	Suppressions []suppressionDoc
	SystemInfo   sysinfoDoc
}

// assetDoc mirrors the web app's Asset entity: its _id is an ObjectId.
type assetDoc struct {
	ID      primitive.ObjectID `bson:"_id"`
	OrgID   string             `bson:"org_id"`
	Type    string             `bson:"type"`
	Enabled bool               `bson:"enabled"`
	Domain  *string            `bson:"domain,omitempty"`
	IP      *string            `bson:"ip,omitempty"`
	AddedOn time.Time          `bson:"added_on"`
	Demo    bool               `bson:"demo"`
}

type discoveryDoc struct {
	shared.Discovery `bson:",inline"`
	Demo             bool `bson:"demo"`
}

// findingDoc has the fields findings_ingestion and the scan monitor write.
type findingDoc struct {
	ID               string         `bson:"_id"`
	OrgID            string         `bson:"org_id"`
	DiscoveryID      string         `bson:"discovery_id"`
	FindingType      string         `bson:"finding_type"`
	Severity         string         `bson:"severity"`
	Source           string         `bson:"source"`
	Title            string         `bson:"title"`
	Description      string         `bson:"description"`
	Remediation      string         `bson:"remediation,omitempty"`
	References       []string       `bson:"references,omitempty"`
	Metadata         map[string]any `bson:"metadata"`
	Status           string         `bson:"status"`
	ScanIDs          []string       `bson:"scan_ids"`
	FirstDetected    time.Time      `bson:"first_detected"`
	LastDetected     time.Time      `bson:"last_detected"`
	ResolvedAt       *time.Time     `bson:"resolved_at,omitempty"`
	ResolvedByScanID string         `bson:"resolved_by_scan_id,omitempty"`
	ResolutionReason string         `bson:"resolution_reason,omitempty"`
	Demo             bool           `bson:"demo"`
}

type scanDoc struct {
	shared.Scan `bson:",inline"`
	Demo        bool `bson:"demo"`
}

type coverageDoc struct {
	ID          primitive.ObjectID  `bson:"_id"`
	ScanID      string              `bson:"scan_id"`
	OrgID       string              `bson:"org_id"`
	Source      string              `bson:"source"`
	DiscoveryID string              `bson:"discovery_id"`
	Target      string              `bson:"target"`
	Status      string              `bson:"status"`
	Reported    []shared.FindingKey `bson:"reported,omitempty"`
	CreatedAt   time.Time           `bson:"created_at"`
	UpdatedAt   time.Time           `bson:"updated_at"`
	Demo        bool                `bson:"demo"`
}

// suppressionDoc mirrors the web app's FindingSuppression entity (finding_suppressions).
type suppressionDoc struct {
	ID           string    `bson:"_id"`
	OrgID        string    `bson:"org_id"`
	DiscoveryID  string    `bson:"discovery_id"`
	FindingType  string    `bson:"finding_type"`
	Status       string    `bson:"status"`
	Note         string    `bson:"note"`
	SuppressedBy string    `bson:"suppressed_by"`
	SuppressedAt time.Time `bson:"suppressed_at"`
	Active       bool      `bson:"active"`
	Demo         bool      `bson:"demo"`
}

type sysinfoDoc struct {
	ID           string `bson:"_id"`
	sysinfo.Info `bson:",inline"`
	Demo         bool `bson:"demo"`
}

var idNamespace = uuid.MustParse("3f1c9d2e-6a7b-4c58-9e0f-a1b2c3d4e5f6")

func demoID(parts ...string) string {
	return uuid.NewSHA1(idNamespace, []byte(strings.Join(parts, "\x00"))).String()
}

// Build returns the sample data for orgID, with scans in the six weeks before now. version is
// the scanner version shown in the About dialog.
func Build(orgID string, now time.Time, version string) *Dataset {
	now = now.UTC().Truncate(time.Minute)
	ds := &Dataset{OrgID: orgID}

	// Scan times: 01:00 UTC on each scan day (weekly schedule); the requested one in the afternoon.
	day := now.Truncate(24 * time.Hour)
	durations := []int{41, 38, 44, 36, 52, 39}
	n := len(scanDaysAgo)
	starts := make([]time.Time, n)
	ends := make([]time.Time, n)
	scanIDs := make([]string, n)
	for i, d := range scanDaysAgo {
		starts[i] = day.AddDate(0, 0, -d).Add(time.Hour)
		if i == requestedScan {
			starts[i] = day.AddDate(0, 0, -d).Add(13*time.Hour + 47*time.Minute)
		}
		ends[i] = starts[i].Add(time.Duration(durations[i%len(durations)]) * time.Minute)
		scanIDs[i] = demoID("scan", orgID, fmt.Sprint(i))
	}
	lastOf := func(last int) int {
		if last == latest {
			return n - 1
		}
		return last
	}
	scansBetween := func(first, last int) []string { return slices.Clone(scanIDs[first : lastOf(last)+1]) }

	// Assets, added a week before the first scan.
	addedOn := starts[0].AddDate(0, 0, -7)
	var targets []shared.AssetTarget
	addAsset := func(typ, value string) {
		a := assetDoc{ID: primitive.NewObjectIDFromTimestamp(addedOn), OrgID: orgID, Type: typ, Enabled: true, AddedOn: addedOn, Demo: true}
		v := value
		if typ == shared.TargetTypeDomain {
			a.Domain = &v
		} else {
			a.IP = &v
		}
		ds.Assets = append(ds.Assets, a)
		targets = append(targets, shared.AssetTarget{AssetID: a.ID.Hex(), Type: typ, Value: value})
	}
	for _, d := range rootDomains {
		addAsset(shared.TargetTypeDomain, d)
	}
	for _, h := range hosts {
		if h.root == "" {
			addAsset(shared.TargetTypeIP, h.ip)
		}
	}

	// Discoveries: the host, its address and its open ports.
	hostIDs := map[string]string{}
	for _, h := range hosts {
		first, last := h.first, lastOf(h.last)
		seenAt := func(i int) time.Time { return starts[i].Add(3 * time.Minute) }
		geo := map[string]any{"continent": h.conti, "country": h.country, "isp": h.isp}
		meta := func(withWAF bool) map[string]any {
			m := map[string]any{"geo": geo}
			if h.cloud != nil {
				c := map[string]any{"provider": h.cloud.provider}
				if h.cloud.region != "" {
					c["region"] = h.cloud.region
				}
				if h.cloud.service != "" {
					c["service"] = h.cloud.service
				}
				m["cloud"] = c
			}
			if withWAF && h.waf != "" {
				m["waf"] = h.waf
			}
			return m
		}
		base := func(id, assetType, source string, parent *string, from int) shared.Discovery {
			return shared.Discovery{
				ID: id, OrgID: orgID, ScanIDs: scansBetween(from, last), AssetType: assetType, Source: source,
				Status: shared.AssetStatusActive, OwnershipStatus: shared.OwnershipStatusVerified,
				DiscoveredAt: seenAt(from), ParentID: parent, FirstSeen: seenAt(from), LastSeen: seenAt(last),
			}
		}

		var ipParent *string
		ipSource := "port_discovery" // a user-added IP: port ingestion creates its discovery
		if h.root != "" {
			id := shared.GenerateSubdomainID(orgID, h.name)
			assetType := shared.AssetTypeSubdomain
			var parent *string
			if h.name == h.root {
				id, assetType = shared.GenerateDomainID(orgID, h.name), shared.AssetTypeDomain
			} else {
				p := shared.GenerateDomainID(orgID, h.root)
				parent = &p
			}
			d := base(id, assetType, "subfinder", parent, first)
			name := h.name
			if assetType == shared.AssetTypeDomain {
				d.Domain = &name
			} else {
				d.Subdomain = &name
			}
			d.ResolutionHistory = []shared.ResolutionHistoryEntry{{IP: h.ip, FirstSeen: seenAt(first)}}
			d.Metadata = meta(true)
			ds.Discoveries = append(ds.Discoveries, discoveryDoc{d, true})
			hostIDs[h.name] = id
			ipParent, ipSource = &id, "subfinder"
		}

		ipID := shared.GenerateIPID(orgID, h.ip)
		if h.root == "" {
			hostIDs[h.name] = ipID
		}
		ipDoc := base(ipID, shared.AssetTypeIP, ipSource, ipParent, first)
		ip := h.ip
		ipDoc.IP = &ip
		ipDoc.Metadata = meta(false)
		if h.cdnEdge != "" {
			ipDoc.Metadata[shared.DiscoveryMetaCDNEdge] = h.cdnEdge
		}
		ds.Discoveries = append(ds.Discoveries, discoveryDoc{ipDoc, true})

		for _, port := range h.ports {
			from := max(first, h.portFrom[port])
			pd := base(shared.GeneratePortID(orgID, h.ip, port, shared.ProtocolTCP), shared.AssetTypePort, "port_discovery", &ipID, from)
			p, proto := port, shared.ProtocolTCP
			pd.IP, pd.Port, pd.Protocol = &ip, &p, &proto
			if b, ok := h.banners[port]; ok {
				pd.Banner = &b
			}
			ds.Discoveries = append(ds.Discoveries, discoveryDoc{pd, true})
		}
	}

	// Findings.
	specs := findings()
	for _, f := range specs {
		discID := hostIDs[f.host]
		last := lastOf(f.last)
		doc := findingDoc{
			ID: demoID("finding", orgID, discID, f.findingType, f.title), OrgID: orgID, DiscoveryID: discID,
			FindingType: f.findingType, Severity: f.severity, Source: f.source, Title: f.title,
			Description: f.description, Remediation: f.remediation, References: f.references,
			Metadata: f.metadata, Status: shared.FindingStatusOpen, ScanIDs: scansBetween(f.first, f.last),
			FirstDetected: starts[f.first].Add(12 * time.Minute), LastDetected: starts[last].Add(12 * time.Minute),
			Demo: true,
		}
		// The email and header scanners also keep the URLs in metadata.references.
		switch f.source {
		case srcEmail:
			doc.Metadata = withKeys(f.metadata, map[string]any{"domain": f.host, "references": f.references})
		case srcHeaders:
			doc.Metadata = withKeys(f.metadata, map[string]any{"references": f.references})
		}
		if f.last != latest {
			resolvedAt := ends[f.last+1]
			doc.Status, doc.ResolvedAt = shared.FindingStatusResolved, &resolvedAt
			doc.ResolvedByScanID, doc.ResolutionReason = scanIDs[f.last+1], reasonNotReproduced
		}
		ds.Findings = append(ds.Findings, doc)
	}

	// Scans, with the counters the scan monitor computes (computeStats; every scan drained).
	reconciled := true
	for i := range n {
		cur := idsInScan(ds, scanIDs[i])
		stats := shared.ScanStats{TotalAssets: len(ds.Assets), TotalDiscoveries: len(cur.discoveries), TotalFindings: len(cur.findings)}
		if i == 0 {
			stats.NewDiscoveries, stats.NewFindings = len(cur.discoveries), len(cur.findings)
		} else {
			prev := idsInScan(ds, scanIDs[i-1])
			stats.NewDiscoveries = countMissing(cur.discoveries, prev.discoveries)
			stats.ResolvedDiscoveries = countMissing(prev.discoveries, cur.discoveries)
			stats.NewFindings = countMissing(cur.findings, prev.findings)
		}
		for _, f := range ds.Findings {
			if f.ResolvedByScanID == scanIDs[i] {
				stats.ResolvedFindings++
			}
		}
		start, end := starts[i], ends[i]
		s := shared.Scan{
			ID: scanIDs[i], OrgID: orgID, Status: shared.StatusDone, Type: shared.ScanTypeScheduled, TriggeredBy: "system",
			StartedAt: &start, CompletedAt: &end, CompletionReason: shared.ScanCompletionPipelineQuiescent,
			FindingsReconciled: &reconciled, CreatedAt: start, UpdatedAt: end, TargetedAssets: targets, Stats: stats,
		}
		if i == requestedScan {
			s.Type, s.TriggeredBy, s.CreatedAt = shared.ScanTypeRequested, "admin", start.Add(-4*time.Second)
		}
		ds.Scans = append(ds.Scans, scanDoc{s, true})
	}

	// Coverage: every check completed on every host it ran on; a host that is gone is absent.
	for i := range n {
		at := starts[i].Add(20 * time.Minute)
		add := func(source, discID, target, status string, reported []shared.FindingKey) {
			ds.Coverage = append(ds.Coverage, coverageDoc{
				ID: primitive.NewObjectIDFromTimestamp(at), ScanID: scanIDs[i], OrgID: orgID, Source: source,
				DiscoveryID: discID, Target: target, Status: status, Reported: reported, CreatedAt: at, UpdatedAt: at, Demo: true,
			})
		}
		for _, h := range hosts {
			seen := i >= h.first && i <= lastOf(h.last)
			if !seen {
				if h.root != "" && i > lastOf(h.last) {
					add(shared.CoverageSourceDomainDiscovery, hostIDs[h.name], h.name, shared.CoverageAbsent, nil)
				}
				continue
			}
			add(shared.CoverageSourcePortDiscovery, shared.GenerateIPID(orgID, h.ip), h.ip, shared.CoverageOK, nil)
			if h.root == "" {
				continue
			}
			sources := hostSources
			if h.name == h.root {
				sources = append(slices.Clone(sources), srcEmail)
			}
			for _, src := range sources {
				if (src == srcTestssl || src == srcJS) && !slices.Contains(h.ports, 443) {
					continue
				}
				target := h.name
				if src == srcTestssl {
					target += ":443"
				}
				var reported []shared.FindingKey
				for _, f := range specs {
					if f.host == h.name && f.source == src && i >= f.first && i <= lastOf(f.last) {
						reported = append(reported, shared.FindingKey{FindingType: f.findingType, Title: f.title})
					}
				}
				add(src, hostIDs[h.name], target, shared.CoverageOK, reported)
			}
		}
	}

	for _, s := range suppressions {
		discID := hostIDs[s.host]
		ds.Suppressions = append(ds.Suppressions, suppressionDoc{
			ID: demoID("suppression", orgID, discID, s.findingType), OrgID: orgID, DiscoveryID: discID,
			FindingType: s.findingType, Status: s.status, Note: s.note, SuppressedBy: "admin",
			SuppressedAt: now.AddDate(0, 0, -s.daysAgo).Add(-3 * time.Hour), Active: true, Demo: true,
		})
	}

	templatesAt := now.AddDate(0, 0, -1).Add(-2 * time.Hour)
	ds.SystemInfo = sysinfoDoc{ID: sysinfo.DocID, Demo: true, Info: sysinfo.Info{
		Version: version, Nuclei: "3.11.1", NucleiTemplates: "v10.5.2", NucleiTemplatesUpdatedAt: &templatesAt,
		TestSSL: "v3.2.5", Retire: "5.4.2", DBIPCountryDate: "2026-11-01", DBIPASNDate: "2026-11-01",
		StartedAt: now.AddDate(0, 0, -3).Add(-5 * time.Hour), UpdatedAt: now,
	}}
	return ds
}

type idSets struct{ discoveries, findings map[string]bool }

func idsInScan(ds *Dataset, scanID string) idSets {
	s := idSets{map[string]bool{}, map[string]bool{}}
	for _, d := range ds.Discoveries {
		if slices.Contains(d.ScanIDs, scanID) {
			s.discoveries[d.ID] = true
		}
	}
	for _, f := range ds.Findings {
		if slices.Contains(f.ScanIDs, scanID) {
			s.findings[f.ID] = true
		}
	}
	return s
}

// countMissing counts the ids of a that are not in b.
func countMissing(a, b map[string]bool) int {
	n := 0
	for id := range a {
		if !b[id] {
			n++
		}
	}
	return n
}

// header returns the finding of a missing-header rule of http_header_scanner, with its texts.
func header(host, findingType string, first, last int) findingSpec {
	for _, r := range scanner.SecurityHeaderRules() {
		if r.FindingType == findingType {
			return findingSpec{
				host: host, source: srcHeaders, findingType: r.FindingType, severity: r.Severity, title: r.Title,
				description: r.Description, references: r.References,
				metadata: map[string]any{"header_name": r.Name, "present": false, "url": "https://" + host,
					"references": r.References, "issue_type": "missing"},
				first: first, last: last,
			}
		}
	}
	panic("demoseed: no header rule " + findingType)
}

func withKeys(m, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func lower(s string) string { return strings.ToLower(s) }

// jsTitle mirrors js_dependency_scanner's formatTitle: "Component version - summary (CVEs)", the
// summary cut to 120 bytes on a word boundary.
func jsTitle(component, version, summary string, cves []string) string {
	const maxSummary = 120
	if len(summary) > maxSummary {
		cut := summary[:maxSummary]
		if i := strings.LastIndexByte(cut, ' '); i > 0 {
			cut = cut[:i]
		}
		summary = cut + "..."
	}
	return fmt.Sprintf("%s %s - %s (%s)", strings.ToUpper(component[:1])+component[1:], version, summary, strings.Join(cves, ", "))
}
