package scan_coordinator

import (
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

const (
	org      = "org-1"
	thisScan = "s3"
)

var (
	recent3 = []string{thisScan, "s2", "s1"}
	portIP  = "203.0.113.7"
	ipID    = shared.GenerateIPID(org, portIP)
)

// evidence builds a resolutionInput for one candidate finding with the given discovery and
// coverage of the closing scan.
func evidence(f findingRef, d *discoveryRef, cov *coverageRef) resolutionInput {
	in := resolutionInput{
		orgID:       org,
		recentScans: recent3,
		candidates:  []findingRef{f},
		discoveries: map[string]discoveryRef{},
		coverage:    map[coverageKey]coverageRef{},
		hostChecks:  map[string]map[coverageKey]bool{},
	}
	if d != nil {
		in.discoveries[d.ID] = *d
	}
	if cov != nil {
		in.coverage[coverageKey{cov.Source, cov.DiscoveryID}] = *cov
	}
	return in
}

// outcome names where decideResolutions put the single candidate.
func outcome(d resolutionDecision) string {
	switch {
	case len(d.notReproduced) == 1:
		return ResolutionNotReproduced
	case len(d.gone) == 1:
		return ResolutionHostNoLongerFound
	case len(d.unchecked) == 1:
		return "open"
	}
	return "?"
}

func headerFinding() findingRef {
	return findingRef{ID: "f1", DiscoveryID: "sub-1", Source: "http-headers", FindingType: "missing-hsts", Title: "Missing HSTS"}
}

func observedSub() *discoveryRef {
	return &discoveryRef{ID: "sub-1", AssetType: shared.AssetTypeSubdomain, Observed: true}
}

func okCoverage(reported ...shared.FindingKey) *coverageRef {
	return &coverageRef{ScanID: thisScan, Source: "http-headers", DiscoveryID: "sub-1", Status: shared.CoverageOK, Reported: reported}
}

// TestDecideResolutions pins the positive-evidence rule: each way a scan can miss data leaves
// the finding open, and only a completed check on a live host that did not report the
// finding again resolves it.
func TestDecideResolutions(t *testing.T) {
	t.Parallel()
	f := headerFinding()

	tests := []struct {
		name string
		in   resolutionInput
		want string
	}{
		{"positive evidence resolves", evidence(f, observedSub(), okCoverage()), ResolutionNotReproduced},
		{"reported again stays open (also when ingestion lost the finding write)",
			evidence(f, observedSub(), okCoverage(shared.FindingKey{FindingType: "missing-hsts", Title: "Missing HSTS"})), "open"},
		{"another finding reported does not keep this one open",
			evidence(f, observedSub(), okCoverage(shared.FindingKey{FindingType: "missing-csp", Title: "Missing CSP"})), ResolutionNotReproduced},
		{"scanner error (no ok coverage) stays open",
			evidence(f, observedSub(), &coverageRef{Source: "http-headers", DiscoveryID: "sub-1", Status: shared.CoverageError}), "open"},
		{"scanner never reported (lost publish, crashed) stays open",
			evidence(f, observedSub(), nil), "open"},
		{"coverage of another scanner does not count",
			evidence(f, observedSub(), &coverageRef{Source: "nuclei", DiscoveryID: "sub-1", Status: shared.CoverageOK}), "open"},
		{"subdomain not observed this scan (NXDOMAIN, subfinder variance) stays open",
			evidence(f, &discoveryRef{ID: "sub-1", AssetType: shared.AssetTypeSubdomain}, okCoverage()), "open"},
		{"missing discovery stays open", evidence(f, nil, okCoverage()), "open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := outcome(decideResolutions(tt.in)); got != tt.want {
				t.Fatalf("outcome = %s, want %s", got, tt.want)
			}
		})
	}
}

// A finding from a nuclei <name>:<port> run on a CDN edge port stays open when an ok coverage
// of the port (from a run by IP) arrives without its key: that run did not check the name.
func TestDecideResolutionsNameRunFindingNotResolvedByPortCoverage(t *testing.T) {
	t.Parallel()
	port := &discoveryRef{ID: "port-1", AssetType: shared.AssetTypePort, IP: portIP, Observed: true}
	cov := &coverageRef{ScanID: thisScan, Source: "nuclei", DiscoveryID: "port-1", Status: shared.CoverageOK}

	byName := findingRef{ID: "f1", DiscoveryID: "port-1", Source: "nuclei", FindingType: "cve-1", Title: "CVE-1"}
	byName.Metadata.ScanHost = "shop.example.com"
	if got := outcome(decideResolutions(evidence(byName, port, cov))); got != "open" {
		t.Fatalf("name-run finding: outcome = %s, want open", got)
	}
	byIP := findingRef{ID: "f2", DiscoveryID: "port-1", Source: "nuclei", FindingType: "cve-1", Title: "CVE-1"}
	if got := outcome(decideResolutions(evidence(byIP, port, cov))); got != ResolutionNotReproduced {
		t.Fatalf("ip-run finding: outcome = %s, want %s", got, ResolutionNotReproduced)
	}
}

func TestDecideResolutionsPortNotObservedStaysOpen(t *testing.T) {
	t.Parallel()
	f := findingRef{ID: "f1", DiscoveryID: "port-1", Source: "nuclei", FindingType: "cve-1", Title: "CVE-1"}
	port := &discoveryRef{ID: "port-1", AssetType: shared.AssetTypePort, IP: portIP} // timed out = not published
	in := evidence(f, port, &coverageRef{Source: "nuclei", DiscoveryID: "port-1", Status: shared.CoverageOK})
	in.hostChecks[thisScan] = map[coverageKey]bool{{shared.CoverageSourcePortDiscovery, ipID}: true}

	if got := outcome(decideResolutions(in)); got != "open" {
		t.Fatalf("outcome = %s, want open: one scan without the port is not proof it closed", got)
	}
}

// TestHostNoLongerFound: a host confirmed gone in goneAfterScans consecutive drained scans
// closes its findings; fewer confirmations, or a gap, keep them open.
func TestHostNoLongerFound(t *testing.T) {
	t.Parallel()
	subKey := coverageKey{shared.CoverageSourceDomainDiscovery, "sub-1"}
	portKey := coverageKey{shared.CoverageSourcePortDiscovery, ipID}
	all := func(k coverageKey, scans ...string) map[string]map[coverageKey]bool {
		m := map[string]map[coverageKey]bool{}
		for _, s := range scans {
			m[s] = map[coverageKey]bool{k: true}
		}
		return m
	}
	sub := &discoveryRef{ID: "sub-1", AssetType: shared.AssetTypeSubdomain}
	port := &discoveryRef{ID: "port-1", AssetType: shared.AssetTypePort, IP: portIP}
	subFinding := headerFinding()
	portFinding := findingRef{ID: "f2", DiscoveryID: "port-1", Source: "nuclei", FindingType: "cve-1", Title: "CVE-1"}

	tests := []struct {
		name   string
		f      findingRef
		d      *discoveryRef
		recent []string
		checks map[string]map[coverageKey]bool
		want   string
	}{
		{"subdomain absent in 3 drained scans", subFinding, sub, recent3, all(subKey, recent3...), ResolutionHostNoLongerFound},
		{"absent in 2 of 3 stays open", subFinding, sub, recent3, all(subKey, "s3", "s2"), "open"},
		{"only 2 drained scans so far stays open", subFinding, sub, []string{"s3", "s2"}, all(subKey, "s3", "s2"), "open"},
		{"absence not recorded this scan stays open", subFinding, sub, recent3, all(subKey, "s2", "s1"), "open"},
		{"port closed in 3 completed port scans", portFinding, port, recent3, all(portKey, recent3...), ResolutionHostNoLongerFound},
		{"port scan did not complete in one scan (CDN skip, failure) stays open", portFinding, port, recent3, all(portKey, "s3", "s1"), "open"},
		{"ip discoveries are never gone", findingRef{ID: "f3", DiscoveryID: "ip-1", Source: "nuclei"},
			&discoveryRef{ID: "ip-1", AssetType: shared.AssetTypeIP, IP: portIP}, recent3, all(portKey, recent3...), "open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := evidence(tt.f, tt.d, nil)
			in.recentScans = tt.recent
			in.hostChecks = tt.checks
			if got := outcome(decideResolutions(in)); got != tt.want {
				t.Fatalf("outcome = %s, want %s", got, tt.want)
			}
		})
	}

	t.Run("port open in one of the scans stays open", func(t *testing.T) {
		t.Parallel()
		seen := *port
		seen.SeenIn = []string{"s2"}
		in := evidence(portFinding, &seen, nil)
		in.hostChecks = all(portKey, recent3...)
		if got := outcome(decideResolutions(in)); got != "open" {
			t.Fatalf("outcome = %s, want open", got)
		}
	})
}

func TestDecideResolutionsSplitsCandidates(t *testing.T) {
	t.Parallel()
	in := evidence(headerFinding(), observedSub(), okCoverage())
	in.candidates = append(in.candidates, findingRef{ID: "f-other", DiscoveryID: "nowhere", Source: "nuclei"})
	d := decideResolutions(in)
	if !slices.Equal(d.notReproduced, []string{"f1"}) || !slices.Equal(d.unchecked, []string{"f-other"}) || len(d.gone) != 0 {
		t.Fatalf("decision = %+v", d)
	}
}

// TestDecideResolutionsSkipsUntargetedAssets: a finding whose discovery belongs only to assets
// the scan did not target (disabled or deleted) is skipped, neither resolved nor unchecked, so
// a disabled asset's findings do not pile up as unchecked. One targeted owner, or no recorded
// owner at all, keeps the usual rules.
func TestDecideResolutionsSkipsUntargetedAssets(t *testing.T) {
	t.Parallel()
	withOwners := func(owners ...string) *discoveryRef {
		d := observedSub()
		d.AssetIDs = owners
		return d
	}
	tests := []struct {
		name   string
		owners []string
		want   string
	}{
		{"only untargeted owners: skipped", []string{"asset-off"}, "skipped"},
		{"shared with a targeted owner: resolved", []string{"asset-off", "asset-on"}, ResolutionNotReproduced},
		{"no recorded owner: resolved", nil, ResolutionNotReproduced},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := evidence(headerFinding(), withOwners(tt.owners...), okCoverage())
			in.targetedAssets = map[string]bool{"asset-on": true}
			d := decideResolutions(in)
			got := outcome(d)
			if len(d.notReproduced)+len(d.gone)+len(d.unchecked) == 0 {
				got = "skipped"
			}
			if got != tt.want {
				t.Fatalf("outcome = %s, want %s (decision %+v)", got, tt.want, d)
			}
		})
	}

	t.Run("untargeted host confirmed gone is not resolved", func(t *testing.T) {
		t.Parallel()
		gone := &discoveryRef{ID: "sub-1", AssetType: shared.AssetTypeSubdomain, AssetIDs: []string{"asset-off"}}
		in := evidence(headerFinding(), gone, nil)
		in.targetedAssets = map[string]bool{"asset-on": true}
		key := coverageKey{shared.CoverageSourceDomainDiscovery, "sub-1"}
		for _, scan := range recent3 {
			in.hostChecks[scan] = map[coverageKey]bool{key: true}
		}
		if d := decideResolutions(in); len(d.gone)+len(d.notReproduced)+len(d.unchecked) != 0 {
			t.Fatalf("decision = %+v, want the finding skipped", d)
		}
	})
}
