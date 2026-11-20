package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.uber.org/zap"
)

const challengePage = "<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>"

// TestFetchHTMLChallengeIsIncomplete: a WAF challenge page has none of the site's scripts, so
// the protocol was not checked.
func TestFetchHTMLChallengeIsIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(challengePage))
	}))
	defer srv.Close()

	_, err := FetchHTML(context.Background(), srv.URL, srv.Client(), zap.NewNop())
	if err == nil || errors.Is(err, shared.ErrGone) || shared.ProbeError(err) == nil {
		t.Fatalf("err = %v, want an incomplete (not gone) error", err)
	}
}

func TestFetchHTMLBlockedStatusIsIncomplete(t *testing.T) {
	for _, code := range []int{403, 429, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		_, err := FetchHTML(context.Background(), srv.URL, srv.Client(), zap.NewNop())
		srv.Close()
		if shared.ProbeError(err) == nil {
			t.Errorf("HTTP %d: complete, want incomplete", code)
		}
	}
}

// TestDownloadFileChallengeFails: a challenge served in place of a script is a failed
// download, not a script without vulnerabilities.
func TestDownloadFileChallengeFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.js":
			w.Write([]byte("var a = 1;"))
		case "/cf.js":
			// A real script that names the challenge variable is still a script.
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("(function(){var o=window._cf_chl_opt||{};})();"))
		default:
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Write([]byte(challengePage))
		}
	}))
	defer srv.Close()
	dir := t.TempDir()

	if err := downloadFile(context.Background(), srv.URL+"/ok.js", filepath.Join(dir, "ok.js"), srv.Client()); err != nil {
		t.Fatalf("plain script: %v", err)
	}
	if err := downloadFile(context.Background(), srv.URL+"/cf.js", filepath.Join(dir, "cf.js"), srv.Client()); err != nil {
		t.Fatalf("script that mentions the challenge: %v", err)
	}
	err := downloadFile(context.Background(), srv.URL+"/app.js", filepath.Join(dir, "app.js"), srv.Client())
	if err == nil || errors.Is(err, shared.ErrGone) {
		t.Fatalf("challenge: err = %v, want a failed download", err)
	}
}
