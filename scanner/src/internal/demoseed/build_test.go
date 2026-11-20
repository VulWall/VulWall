package demoseed

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

var testNow = time.Date(2026, 11, 20, 15, 30, 0, 0, time.UTC)

func TestBuildUsesReservedNamesAndDocumentationAddresses(t *testing.T) {
	docRanges := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	}
	inDocRange := func(s string) bool {
		a, err := netip.ParseAddr(s)
		return err == nil && slices.ContainsFunc(docRanges, func(p netip.Prefix) bool { return p.Contains(a) })
	}
	ds := Build("org1", testNow, "v0.1.0")
	for _, d := range ds.Discoveries {
		for _, name := range []*string{d.Domain, d.Subdomain} {
			if name != nil && !strings.HasSuffix(*name, ".test") {
				t.Errorf("host %q is not under .test", *name)
			}
		}
		if d.IP != nil && !inDocRange(*d.IP) {
			t.Errorf("address %q is not in a documentation range", *d.IP)
		}
	}
	for _, a := range ds.Assets {
		if a.Domain != nil && !strings.HasSuffix(*a.Domain, ".test") || a.IP != nil && !inDocRange(*a.IP) {
			t.Errorf("asset %v/%v is not reserved", a.Domain, a.IP)
		}
	}
}

func TestBuildMarksEveryDocumentAndKeepsReferencesConsistent(t *testing.T) {
	ds := Build("org1", testNow, "v0.1.0")
	discoveries := map[string]discoveryDoc{}
	for _, d := range ds.Discoveries {
		if !d.Demo || d.OrgID != "org1" {
			t.Fatalf("discovery %s: demo=%v org=%s", d.ID, d.Demo, d.OrgID)
		}
		if _, dup := discoveries[d.ID]; dup {
			t.Fatalf("duplicate discovery id %s", d.ID)
		}
		discoveries[d.ID] = d
	}
	scans := map[string]bool{}
	for _, s := range ds.Scans {
		if !s.Demo || s.Status != shared.StatusDone || s.CompletionReason != shared.ScanCompletionPipelineQuiescent ||
			s.FindingsReconciled == nil || !*s.FindingsReconciled {
			t.Fatalf("scan %s is not a drained demo scan: %+v", s.ID, s.Scan)
		}
		scans[s.ID] = true
	}
	for _, d := range ds.Discoveries {
		if d.ParentID != nil {
			if _, ok := discoveries[*d.ParentID]; !ok {
				t.Errorf("discovery %s: parent %s missing", d.ID, *d.ParentID)
			}
		}
		for _, id := range d.ScanIDs {
			if !scans[id] {
				t.Errorf("discovery %s: unknown scan %s", d.ID, id)
			}
		}
	}
	keys := map[[4]string]bool{}
	for _, f := range ds.Findings {
		if !f.Demo {
			t.Fatalf("finding %s not marked", f.ID)
		}
		if _, ok := discoveries[f.DiscoveryID]; !ok {
			t.Errorf("finding %s: discovery %s missing", f.Title, f.DiscoveryID)
		}
		k := [4]string{f.OrgID, f.DiscoveryID, f.FindingType, f.Title}
		if keys[k] {
			t.Errorf("finding dedup key repeated: %v", k)
		}
		keys[k] = true
		if f.Status == shared.FindingStatusResolved && (f.ResolvedAt == nil || !scans[f.ResolvedByScanID] ||
			f.ResolutionReason != reasonNotReproduced || slices.Contains(f.ScanIDs, f.ResolvedByScanID)) {
			t.Errorf("finding %s: inconsistent resolution", f.Title)
		}
		if f.Status == shared.FindingStatusOpen && (f.ResolvedAt != nil || f.ResolvedByScanID != "") {
			t.Errorf("open finding %s has resolution fields", f.Title)
		}
	}
	for _, s := range ds.Suppressions {
		if !s.Demo || !slices.ContainsFunc(ds.Findings, func(f findingDoc) bool {
			return f.DiscoveryID == s.DiscoveryID && f.FindingType == s.FindingType && f.Status == shared.FindingStatusOpen
		}) {
			t.Errorf("suppression %s/%s matches no open finding", s.DiscoveryID, s.FindingType)
		}
	}
	for _, c := range ds.Coverage {
		if !c.Demo || !scans[c.ScanID] {
			t.Errorf("coverage %+v not marked or unknown scan", c)
		}
	}
	if !ds.SystemInfo.Demo || ds.SystemInfo.Version != "v0.1.0" {
		t.Errorf("system_info = %+v", ds.SystemInfo)
	}
}

// Stats follow the scan monitor: totals are what the scan saw, new/resolved compare with the
// previous scan, resolved_findings counts the findings the scan resolved.
func TestBuildScanStatsMatchTheDocuments(t *testing.T) {
	ds := Build("org1", testNow, "v0.1.0")
	totalResolved := 0
	for i, s := range ds.Scans {
		cur := idsInScan(ds, s.ID)
		if s.Stats.TotalFindings != len(cur.findings) || s.Stats.TotalDiscoveries != len(cur.discoveries) ||
			s.Stats.TotalAssets != len(ds.Assets) {
			t.Errorf("scan %d totals %+v", i, s.Stats)
		}
		if i > 0 {
			prev := idsInScan(ds, ds.Scans[i-1].ID)
			if s.Stats.NewFindings != countMissing(cur.findings, prev.findings) {
				t.Errorf("scan %d new_findings %d", i, s.Stats.NewFindings)
			}
		}
		totalResolved += s.Stats.ResolvedFindings
	}
	resolved := 0
	for _, f := range ds.Findings {
		if f.Status == shared.FindingStatusResolved {
			resolved++
		}
	}
	if totalResolved != resolved || resolved < 5 {
		t.Errorf("resolved_findings sum %d, resolved findings %d (want at least 5)", totalResolved, resolved)
	}
}

// The screens the sample data is for: a declining trend, three items under "Fix these first",
// and every scan on its own day.
func TestBuildFillsTheOverview(t *testing.T) {
	ds := Build("org1", testNow, "v0.1.0")
	days := map[time.Time]bool{}
	weighted := func(scanID string) int {
		groups := map[string]int{}
		for _, f := range ds.Findings {
			if slices.Contains(f.ScanIDs, scanID) {
				groups[f.Source+"|"+f.FindingType+"|"+f.Severity] = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}[f.Severity]
			}
		}
		sum := 0
		for _, w := range groups {
			sum += w
		}
		return sum
	}
	for i, s := range ds.Scans {
		day := s.CreatedAt.Truncate(24 * time.Hour)
		if days[day] {
			t.Errorf("two scans on %s", day)
		}
		days[day] = true
		if !s.CreatedAt.Before(testNow) || s.CreatedAt.Before(testNow.AddDate(0, 0, -45)) {
			t.Errorf("scan %d at %s is outside the six weeks before now", i, s.CreatedAt)
		}
	}
	first, last := weighted(ds.Scans[0].ID), weighted(ds.Scans[len(ds.Scans)-1].ID)
	if last >= first {
		t.Errorf("trend does not decline: first scan %d, latest %d", first, last)
	}

	latestID := ds.Scans[len(ds.Scans)-1].ID
	suppressed := map[string]bool{}
	for _, s := range ds.Suppressions {
		suppressed[s.DiscoveryID+s.FindingType] = true
	}
	fixFirst := map[string]bool{}
	for _, f := range ds.Findings {
		if slices.Contains(f.ScanIDs, latestID) && !suppressed[f.DiscoveryID+f.FindingType] &&
			(f.Severity == shared.SeverityCritical || f.Severity == shared.SeverityHigh) {
			fixFirst[f.FindingType] = true
		}
	}
	// The web app caps the score at 30 with two critical finding types and at 49 with one, so
	// fixing a critical in the latest scan is what makes the score rise.
	criticalTypes := func(scanID string) int {
		types := map[string]bool{}
		for _, f := range ds.Findings {
			if f.Severity == shared.SeverityCritical && slices.Contains(f.ScanIDs, scanID) {
				types[f.FindingType] = true
			}
		}
		return len(types)
	}
	if prev, cur := criticalTypes(ds.Scans[len(ds.Scans)-2].ID), criticalTypes(latestID); prev != 2 || cur != 1 {
		t.Errorf("critical finding types: previous scan %d, latest %d; want 2 then 1", prev, cur)
	}
	if len(fixFirst) < 3 {
		t.Errorf("latest scan has %d critical/high finding types, want 3: %v", len(fixFirst), fixFirst)
	}
}

func TestJSTitleMatchesTheScannerFormat(t *testing.T) {
	got := jsTitle("jquery", "1.12.4", "Regex in its jQuery.htmlPrefilter sometimes may introduce XSS", []string{"CVE-2020-11022"})
	if want := "Jquery 1.12.4 - Regex in its jQuery.htmlPrefilter sometimes may introduce XSS (CVE-2020-11022)"; got != want {
		t.Errorf("got %q", got)
	}
	long := strings.Repeat("word ", 40)
	if got := jsTitle("x", "1", long, []string{"CVE-1"}); !strings.Contains(got, "...") || len(got) > 140 {
		t.Errorf("long summary not cut: %q", got)
	}
}

// The knowledge-base entries follow the KB engine's response schema and belong to finding
// types that are open in the latest scan, so the Recommendations tiles count them.
func TestBuildKnowledgeBaseEntries(t *testing.T) {
	ds := Build("org1", testNow, "v0.1.0")
	latestID := ds.Scans[len(ds.Scans)-1].ID
	exploitable, quick := 0, 0
	for _, kb := range ds.Knowledge {
		if !kb.Demo || !kb.Published || kb.ID != "kb_"+kb.FindingType {
			t.Errorf("%s: demo=%v published=%v id=%s", kb.FindingType, kb.Demo, kb.Published, kb.ID)
		}
		if !slices.ContainsFunc(ds.Findings, func(f findingDoc) bool {
			return f.FindingType == kb.FindingType && slices.Contains(f.ScanIDs, latestID)
		}) {
			t.Errorf("%s: no finding of this type in the latest scan", kb.FindingType)
		}
		b, m := kb.Business, kb.Metadata
		if !slices.Contains([]string{"immediate", "high", "medium", "low"}, b.Urgency) ||
			!slices.Contains([]string{"trivial", "small", "medium", "large"}, m.EstimatedEffort) ||
			b.Title == "" || b.Summary == "" || len(b.Actions) < 2 || len(kb.Technical.RemediationSteps) == 0 {
			t.Errorf("%s: entry does not follow the schema: %+v", kb.FindingType, kb)
		}
		if m.IsExploitable {
			exploitable++
		}
		if m.EstimatedEffort == "trivial" || m.EstimatedEffort == "small" {
			quick++
		}
	}
	if len(ds.Knowledge) < 3 || exploitable == 0 || quick == 0 {
		t.Errorf("%d entries, %d exploitable, %d quick wins", len(ds.Knowledge), exploitable, quick)
	}
}
