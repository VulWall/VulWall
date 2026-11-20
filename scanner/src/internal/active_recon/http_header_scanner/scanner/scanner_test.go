package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"go.uber.org/zap"
)

// TestScanIncompleteOnBlockedStatus: an error page (WAF block, outage) may not carry the
// application's headers, so the check reports its findings but is incomplete.
func TestScanIncompleteOnBlockedStatus(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true") // httptest listens on loopback
	for status, wantIncomplete := range map[int]bool{200: false, 404: false, 403: true, 429: true, 503: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		results, err := NewScanner(zap.NewNop()).Scan(context.Background(), srv.URL)
		srv.Close()
		if (err != nil) != wantIncomplete {
			t.Errorf("HTTP %d: err = %v, want incomplete %v", status, err, wantIncomplete)
		}
		if len(results) == 0 {
			t.Errorf("HTTP %d: no results, want the missing-header findings reported either way", status)
		}
	}
}

// TestScanIncompleteWhenTargetGoesAway: a sub-request that fails makes the check incomplete
// instead of silently dropping its finding.
func TestScanIncompleteWhenTargetGoesAway(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls > 1 {
			// Drop the connection on the CORS and redirect requests.
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
	}))
	defer srv.Close()
	if _, err := NewScanner(zap.NewNop()).Scan(context.Background(), srv.URL); err == nil {
		t.Fatal("err = nil, want incomplete: the CORS and redirect checks did not get an answer")
	}
}

// TestScanIncompleteOnChallengePage: a WAF challenge served with 200 carries the WAF's
// headers, not the application's.
func TestScanIncompleteOnChallengePage(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	for name, h := range map[string]http.HandlerFunc{
		"challenge page": func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>"))
		},
		"cf-mitigated header": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("cf-mitigated", "challenge")
		},
	} {
		srv := httptest.NewServer(h)
		_, err := NewScanner(zap.NewNop()).Scan(context.Background(), srv.URL)
		srv.Close()
		if err == nil {
			t.Errorf("%s: err = nil, want incomplete", name)
		}
	}
}
