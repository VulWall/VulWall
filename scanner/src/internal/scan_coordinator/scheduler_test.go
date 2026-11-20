package scan_coordinator

import (
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

func newTestScheduler() *Scheduler {
	return NewScheduler(nil, nil, nil, zap.NewNop())
}

func testOrg(id, cronExpr string, enabled *bool) shared.Organization {
	return shared.Organization{ID: id, ScanSettings: shared.ScanSettings{ScanCron: cronExpr, Enabled: enabled}}
}

func boolPtr(b bool) *bool { return &b }

// scheduled returns org_id -> cron of the organizations with a live cron entry.
func scheduled(t *testing.T, sc *Scheduler) map[string]string {
	t.Helper()
	live := map[cron.EntryID]bool{}
	for _, e := range sc.cron.Entries() {
		live[e.ID] = true
	}
	got := map[string]string{}
	for id, e := range sc.entries {
		if e.entryID != 0 {
			if !live[e.entryID] {
				t.Fatalf("org %s points at removed cron entry %d", id, e.entryID)
			}
			got[id] = e.cronExpr
		}
	}
	if len(got) != len(sc.cron.Entries()) {
		t.Fatalf("%d tracked entries, %d cron entries", len(got), len(sc.cron.Entries()))
	}
	return got
}

func TestApplySchedules_SkipsDisabledAndEmpty(t *testing.T) {
	sc := newTestScheduler()
	sc.applySchedules([]shared.Organization{
		testOrg("on", "0 2 * * *", boolPtr(true)),
		testOrg("missing-flag", "0 3 * * *", nil), // documents without "enabled" count as on
		testOrg("off", "0 4 * * *", boolPtr(false)),
		testOrg("no-cron", "", boolPtr(true)),
	})

	got := scheduled(t, sc)
	want := map[string]string{"on": "0 2 * * *", "missing-flag": "0 3 * * *"}
	if len(got) != len(want) {
		t.Fatalf("scheduled = %v, want %v", got, want)
	}
	for id, c := range want {
		if got[id] != c {
			t.Errorf("org %s cron = %q, want %q", id, got[id], c)
		}
	}
}

func TestApplySchedules_RefreshPicksUpChanges(t *testing.T) {
	sc := newTestScheduler()
	sc.applySchedules([]shared.Organization{
		testOrg("a", "0 2 * * 6", nil),
		testOrg("b", "0 3 * * 0", nil),
	})
	keptID := sc.entries["b"].entryID

	// a's schedule changes; b is unchanged.
	sc.applySchedules([]shared.Organization{
		testOrg("a", "30 1 * * *", nil),
		testOrg("b", "0 3 * * 0", nil),
	})
	got := scheduled(t, sc)
	if got["a"] != "30 1 * * *" {
		t.Errorf("a cron = %q, want the new schedule", got["a"])
	}
	if sc.entries["b"].entryID != keptID {
		t.Errorf("unchanged org b was rescheduled (entry %d -> %d)", keptID, sc.entries["b"].entryID)
	}

	// a is turned off, b's org is deleted.
	sc.applySchedules([]shared.Organization{testOrg("a", "30 1 * * *", boolPtr(false))})
	if got := scheduled(t, sc); len(got) != 0 {
		t.Errorf("scheduled = %v, want none", got)
	}

	// a is turned back on.
	sc.applySchedules([]shared.Organization{testOrg("a", "30 1 * * *", boolPtr(true))})
	if got := scheduled(t, sc); got["a"] != "30 1 * * *" || len(got) != 1 {
		t.Errorf("scheduled = %v, want only a", got)
	}
}

func TestApplySchedules_InvalidCronIsNotScheduledUntilFixed(t *testing.T) {
	sc := newTestScheduler()
	sc.applySchedules([]shared.Organization{testOrg("a", "not a cron", nil)})
	if got := scheduled(t, sc); len(got) != 0 {
		t.Fatalf("scheduled = %v, want none", got)
	}
	if _, tracked := sc.entries["a"]; !tracked {
		t.Fatal("invalid cron should be remembered so a refresh does not retry and re-log it")
	}

	sc.applySchedules([]shared.Organization{testOrg("a", "15 4 1 * *", nil)})
	if got := scheduled(t, sc); got["a"] != "15 4 1 * *" {
		t.Errorf("scheduled = %v, want the fixed cron", got)
	}
}

// TestStandardParserAcceptsWebCrons checks that the scanner accepts every shape the web
// app's schedule form writes: daily, weekly (day of week 0-6) and monthly (day 1-28).
func TestStandardParserAcceptsWebCrons(t *testing.T) {
	for _, c := range []string{"0 0 * * *", "59 23 * * *", "37 3 * * 0", "37 3 * * 6", "0 2 1 * *", "45 22 28 * *"} {
		if _, err := cron.ParseStandard(c); err != nil {
			t.Errorf("ParseStandard(%q): %v", c, err)
		}
	}
}
