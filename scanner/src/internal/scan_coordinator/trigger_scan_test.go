package scan_coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

type fakePreconditions struct {
	exists     bool
	running    bool
	runningErr error
}

func (f fakePreconditions) orgExists(context.Context, string) (bool, error) {
	return f.exists, nil
}

func (f fakePreconditions) hasRunningScan(context.Context, string) (bool, error) {
	return f.running, f.runningErr
}

// newTestService returns a Service without MongoDB or Redis. It is only safe
// for paths that return before getOrgAssets is called.
func newTestService(checks scanPreconditions) *Service {
	return &Service{
		logger: zap.NewNop(),
		tracer: otel.Tracer("test"),
		checks: checks,
	}
}

func TestTriggerScanRejectsWhenScanRunning(t *testing.T) {
	svc := newTestService(fakePreconditions{exists: true, running: true})

	scanID, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1", Type: "requested", TriggeredBy: "u"})

	if !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("err = %v, want ErrScanInProgress", err)
	}
	if scanID != "" {
		t.Fatalf("scanID = %q, want empty", scanID)
	}
}

func TestTriggerScanOrgNotFoundBeforeRunningCheck(t *testing.T) {
	svc := newTestService(fakePreconditions{exists: false, running: true})

	_, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1"})

	if !errors.Is(err, ErrOrgNotFound) {
		t.Fatalf("err = %v, want ErrOrgNotFound", err)
	}
}

func TestTriggerScanRunningCheckErrorIsWrapped(t *testing.T) {
	boom := errors.New("mongo down")
	svc := newTestService(fakePreconditions{exists: true, runningErr: boom})

	_, err := svc.TriggerScan(context.Background(), ScanRequest{OrgID: "org-1"})

	if !errors.Is(err, boom) || errors.Is(err, ErrScanInProgress) {
		t.Fatalf("err = %v, want wrapped mongo error", err)
	}
}

func TestHandleTriggerScanReturns409WhenScanRunning(t *testing.T) {
	api := NewAPIServer(newTestService(fakePreconditions{exists: true, running: true}), zap.NewNop(), "0", "key")
	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(`{"org_id":"org-1","triggered_by":"u"}`))
	req.Header.Set("X-API-Key", "key")
	rec := httptest.NewRecorder()

	api.server.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body errorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil || body.Error == "" {
		t.Fatalf("body = %q, err = %v; want JSON error", rec.Body.String(), err)
	}
}
