package scan_coordinator

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// fakeStore is an in-memory scanStore. Scans are keyed by _id.
type fakeStore struct {
	orgs      map[string]bool
	assets    map[string][]shared.Asset
	scans     map[string]shared.Scan
	set       map[string]bson.M // last $set applied per scan
	inserted  []shared.Scan
	activeErr error
	known     map[string][]string // by orgID/parentID
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		orgs:   map[string]bool{},
		assets: map[string][]shared.Asset{},
		scans:  map[string]shared.Scan{},
		set:    map[string]bson.M{},
	}
}

func (f *fakeStore) orgExists(_ context.Context, orgID string) (bool, error) {
	return f.orgs[orgID], nil
}

func (f *fakeStore) hasScanIn(_ context.Context, orgID string, statuses []string) (bool, error) {
	if f.activeErr != nil {
		return false, f.activeErr
	}
	for _, s := range f.scans {
		if s.OrgID == orgID && slices.Contains(statuses, s.Status) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) orgAssets(_ context.Context, orgID string) ([]shared.Asset, error) {
	return f.assets[orgID], nil
}

func (f *fakeStore) knownSubdomains(_ context.Context, orgID, parentID string) ([]string, error) {
	return f.known[orgID+"/"+parentID], nil
}

func (f *fakeStore) insertScan(_ context.Context, scan shared.Scan) error {
	f.inserted = append(f.inserted, scan)
	f.scans[scan.ID] = scan
	return nil
}

func (f *fakeStore) queuedScans(context.Context) ([]shared.Scan, error) {
	var out []shared.Scan
	for _, s := range f.scans {
		if s.Status == shared.StatusQueued {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b shared.Scan) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

func (f *fakeStore) claimQueuedScan(ctx context.Context, scanID string, set bson.M) (bool, error) {
	s, ok := f.scans[scanID]
	if !ok || s.Status != shared.StatusQueued {
		return false, nil
	}
	return true, f.setScanFields(ctx, scanID, set)
}

func (f *fakeStore) setScanFields(ctx context.Context, scanID string, set bson.M) error {
	// Like the MongoDB driver, refuse to write with a cancelled context.
	if err := ctx.Err(); err != nil {
		return err
	}
	s := f.scans[scanID]
	if status, ok := set["status"].(string); ok {
		s.Status = status
	}
	f.scans[scanID] = s
	f.set[scanID] = set
	return nil
}

func (f *fakeStore) setStartedScans(ctx context.Context, set bson.M) (int64, error) {
	var n int64
	for id, s := range f.scans {
		if slices.Contains(startedStatuses, s.Status) {
			if err := f.setScanFields(ctx, id, set); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// publishedJob records one call to the jobPublisher.
type publishedJob struct {
	stream string
	job    any
}

func newTestService(store scanStore, publishErr error) (*Service, *[]publishedJob) {
	var published []publishedJob
	return &Service{
		store: store,
		publish: func(_ context.Context, stream string, job any) error {
			if publishErr != nil {
				return publishErr
			}
			published = append(published, publishedJob{stream, job})
			return nil
		},
		logger: zap.NewNop(),
		tracer: otel.Tracer("test"),
	}, &published
}

func strPtr(s string) *string { return &s }

func domainAsset(id, domain string) shared.Asset {
	return shared.Asset{ID: id, Type: "domain", Domain: strPtr(domain), Enabled: true}
}

func TestTriggerScanRejectsWhenScanActive(t *testing.T) {
	for _, status := range []string{shared.StatusQueued, shared.StatusPending, shared.StatusRunning} {
		store := newFakeStore()
		store.orgs["org-1"] = true
		store.scans["s0"] = shared.Scan{ID: "s0", OrgID: "org-1", Status: status}
		svc, _ := newTestService(store, nil)

		scanID, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1", Type: shared.ScanTypeScheduled, TriggeredBy: "system"})

		if !errors.Is(err, ErrScanInProgress) {
			t.Fatalf("status %q: err = %v, want ErrScanInProgress", status, err)
		}
		if scanID != "" || len(store.inserted) != 0 {
			t.Fatalf("status %q: scan created despite active scan", status)
		}
	}
}

func TestTriggerScanOrgNotFoundBeforeRunningCheck(t *testing.T) {
	store := newFakeStore()
	store.activeErr = errors.New("must not be called")
	svc, _ := newTestService(store, nil)

	_, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1"})

	if !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("err = %v, want ErrOrgNotFound", err)
	}
}

func TestTriggerScanRunningCheckErrorIsWrapped(t *testing.T) {
	boom := errors.New("mongo down")
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.activeErr = boom
	svc, _ := newTestService(store, nil)

	_, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1"})

	if !errors.Is(err, boom) || errors.Is(err, ErrScanInProgress) {
		t.Fatalf("err = %v, want wrapped mongo error", err)
	}
}

func TestTriggerScanCreatesRunningScanAndPublishes(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.assets["org-1"] = []shared.Asset{domainAsset("a1", "https://example.com/path")}
	store.known = map[string][]string{"org-1/" + shared.GenerateDomainID("org-1", "example.com"): {"old.example.com"}}
	svc, published := newTestService(store, nil)

	scanID, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1", Type: shared.ScanTypeScheduled, TriggeredBy: "system"})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}

	got := store.inserted[0]
	if got.ID != scanID || got.Status != shared.StatusRunning || got.StartedAt == nil || got.Stats.TotalAssets != 1 {
		t.Fatalf("inserted scan = %+v", got)
	}
	if len(*published) != 1 || (*published)[0].stream != shared.StreamDomainDiscoveryQueue {
		t.Fatalf("published = %+v, want one domain job", *published)
	}
	job := (*published)[0].job.(shared.DiscoveryJob)
	if job.Host != "example.com" || job.ScanID == nil || *job.ScanID != scanID {
		t.Fatalf("job = %+v", job)
	}
	if len(job.KnownSubdomains) != 1 || job.KnownSubdomains[0] != "old.example.com" {
		t.Fatalf("known subdomains = %v, want the names earlier scans saw below the domain", job.KnownSubdomains)
	}
}

func TestTriggerScanMarksFailedWhenAllPublishesFail(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.assets["org-1"] = []shared.Asset{domainAsset("a1", "example.com")}
	svc, _ := newTestService(store, errors.New("redis down"))

	_, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1"})

	if err == nil {
		t.Fatal("err = nil, want publish error")
	}
	if s := store.scans[store.inserted[0].ID]; s.Status != shared.StatusFailed {
		t.Fatalf("status = %q, want failed", s.Status)
	}
}

func queuedScan(id, orgID string, created time.Time) shared.Scan {
	return shared.Scan{ID: id, OrgID: orgID, Status: shared.StatusQueued, TriggeredBy: "user-1", CreatedAt: created}
}

func TestQueuedScanIsClaimedInPlace(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.assets["org-1"] = []shared.Asset{domainAsset("a1", "example.com")}
	store.scans["q1"] = queuedScan("q1", "org-1", time.Now())
	svc, published := newTestService(store, nil)

	svc.startQueuedScans(context.Background())

	if len(store.inserted) != 0 {
		t.Fatalf("poller inserted %d scans; it must reuse the queued _id", len(store.inserted))
	}
	set := store.set["q1"]
	if set["status"] != shared.StatusRunning || set["type"] != shared.ScanTypeRequested ||
		set["stats.total_assets"] != 1 || set["started_at"] == nil || set["updated_at"] == nil {
		t.Fatalf("claim $set = %+v", set)
	}
	if targets := set["targeted_assets"].([]shared.AssetTarget); len(targets) != 1 || targets[0].Value != "example.com" {
		t.Fatalf("targeted_assets = %+v", targets)
	}
	if len(*published) != 1 || *(*published)[0].job.(shared.DiscoveryJob).ScanID != "q1" {
		t.Fatalf("published = %+v, want one job for scan q1", *published)
	}
}

func TestQueuedScanWaitsWhileOrgHasRunningScan(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.assets["org-1"] = []shared.Asset{domainAsset("a1", "example.com")}
	store.scans["r1"] = shared.Scan{ID: "r1", OrgID: "org-1", Status: shared.StatusRunning}
	store.scans["q1"] = queuedScan("q1", "org-1", time.Now())
	svc, published := newTestService(store, nil)

	svc.startQueuedScans(context.Background())

	if store.scans["q1"].Status != shared.StatusQueued || len(*published) != 0 {
		t.Fatalf("queued scan started while another scan runs")
	}

	// The running scan finishes; the next poll starts the queued one.
	r1 := store.scans["r1"]
	r1.Status = shared.StatusDone
	store.scans["r1"] = r1
	svc.startQueuedScans(context.Background())

	if store.scans["q1"].Status != shared.StatusRunning {
		t.Fatalf("status = %q, want running after the other scan finished", store.scans["q1"].Status)
	}
}

func TestOnlyOldestQueuedScanPerOrgStartsPerPoll(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.assets["org-1"] = []shared.Asset{domainAsset("a1", "example.com")}
	now := time.Now()
	store.scans["new"] = queuedScan("new", "org-1", now)
	store.scans["old"] = queuedScan("old", "org-1", now.Add(-time.Minute))
	svc, _ := newTestService(store, nil)

	svc.startQueuedScans(context.Background())

	if store.scans["old"].Status != shared.StatusRunning || store.scans["new"].Status != shared.StatusQueued {
		t.Fatalf("old=%q new=%q, want old running and new queued", store.scans["old"].Status, store.scans["new"].Status)
	}
}

func TestQueuedScanForMissingOrgIsFailed(t *testing.T) {
	store := newFakeStore()
	store.scans["q1"] = queuedScan("q1", "gone", time.Now())
	svc, _ := newTestService(store, nil)

	svc.startQueuedScans(context.Background())

	if store.scans["q1"].Status != shared.StatusFailed || store.set["q1"]["completed_at"] == nil {
		t.Fatalf("scan = %+v set = %+v, want failed with completed_at", store.scans["q1"], store.set["q1"])
	}
}

func TestQueuedScanWithoutAssetsIsDoneImmediately(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.scans["q1"] = queuedScan("q1", "org-1", time.Now())
	svc, published := newTestService(store, nil)

	svc.startQueuedScans(context.Background())

	if store.scans["q1"].Status != shared.StatusDone || store.set["q1"]["completed_at"] == nil ||
		store.set["q1"]["findings_reconciled"] != false || len(*published) != 0 {
		t.Fatalf("scan = %+v, want done with no jobs", store.scans["q1"])
	}
}

func TestQueuedScanPublishFailureMarksFailed(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.assets["org-1"] = []shared.Asset{domainAsset("a1", "example.com")}
	store.scans["q1"] = queuedScan("q1", "org-1", time.Now())
	svc, _ := newTestService(store, errors.New("redis down"))

	svc.startQueuedScans(context.Background())

	if store.scans["q1"].Status != shared.StatusFailed {
		t.Fatalf("status = %q, want failed", store.scans["q1"].Status)
	}
}

func TestScheduledTriggerSkippedWhileScanQueued(t *testing.T) {
	store := newFakeStore()
	store.orgs["org-1"] = true
	store.scans["q1"] = queuedScan("q1", "org-1", time.Now())
	svc, _ := newTestService(store, nil)

	if _, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1", Type: shared.ScanTypeScheduled}); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("err = %v, want ErrScanInProgress", err)
	}
}

func TestScanStartTimePrefersStartedAt(t *testing.T) {
	created := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	started := created.Add(2 * time.Hour)

	if got := scanStartTime(shared.Scan{CreatedAt: created}); !got.Equal(created) {
		t.Fatalf("without started_at: got %v, want created_at", got)
	}
	if got := scanStartTime(shared.Scan{CreatedAt: created, StartedAt: &started}); !got.Equal(started) {
		t.Fatalf("with started_at: got %v, want started_at", got)
	}
}

func TestMarkFailedWritesAfterContextCancelled(t *testing.T) {
	store := newFakeStore()
	store.scans["s1"] = shared.Scan{ID: "s1", OrgID: "org-1", Status: shared.StatusRunning}
	svc, _ := newTestService(store, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a shutdown cancelled the publish that failed

	svc.markFailed(ctx, "s1", context.Canceled)

	if store.scans["s1"].Status != shared.StatusFailed {
		t.Fatalf("status = %q, want failed even though ctx was cancelled", store.scans["s1"].Status)
	}
}

func TestCloseInterruptedScansFailsOnlyStartedScans(t *testing.T) {
	store := newFakeStore()
	for id, status := range map[string]string{
		"pending": shared.StatusPending,
		"running": shared.StatusRunning,
		"queued":  shared.StatusQueued,
		"done":    shared.StatusDone,
		"failed":  shared.StatusFailed,
	} {
		store.scans[id] = shared.Scan{ID: id, OrgID: "org-1", Status: status}
	}
	svc, published := newTestService(store, nil)

	n, err := svc.CloseInterruptedScans(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("n = %d err = %v, want 2 closed", n, err)
	}

	for _, id := range []string{"pending", "running"} {
		set := store.set[id]
		if store.scans[id].Status != shared.StatusFailed ||
			set["status_reason"] != shared.ScanReasonInterruptedByRestart ||
			set["completion_reason"] != shared.ScanReasonInterruptedByRestart ||
			set["findings_reconciled"] != false ||
			set["completed_at"] == nil {
			t.Errorf("%s: status = %q set = %+v, want failed/interrupted_by_restart with completed_at",
				id, store.scans[id].Status, set)
		}
	}
	for id, want := range map[string]string{"queued": shared.StatusQueued, "done": shared.StatusDone, "failed": shared.StatusFailed} {
		if store.scans[id].Status != want {
			t.Errorf("%s: status = %q, want unchanged %q", id, store.scans[id].Status, want)
		}
		if _, touched := store.set[id]; touched {
			t.Errorf("%s: was written, want untouched", id)
		}
	}
	if len(*published) != 0 {
		t.Errorf("published %d jobs, want none", len(*published))
	}
}
