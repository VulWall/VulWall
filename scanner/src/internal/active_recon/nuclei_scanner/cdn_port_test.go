package nuclei_scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// A CDN edge port whose origin does not answer (Cloudflare 522) is not scanned at all: nuclei
// would wait minutes and drop it. Nothing is published, not even coverage.
func TestProcessCDNPortSkipsPortWithoutAnswer(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(522)
	}))
	defer origin.Close()
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	if err := os.WriteFile(filepath.Join(dir, "nuclei"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// redis nil: any publish would panic.
	s := &Service{logger: zap.NewNop(), tracer: otel.Tracer("test"), rootClient: newRootClient()}
	if err := s.ProcessCDNPort(context.Background(), ScanTarget{Target: origin.URL, DiscoveryID: "p1", OrgID: "org"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("nuclei ran on a CDN port that does not answer")
	}
}

// TestProcessCDNPortPublishesFindingsWithoutCoverage checks against a real Redis
// (VULWALL_TEST_REDIS_URI) that a CDN port run by name publishes its matches and no coverage:
// it is no evidence for the port discovery.
func TestProcessCDNPortPublishesFindingsWithoutCoverage(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_REDIS_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	ctx := context.Background()
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer site.Close()
	fakeNuclei(t, twoMatches, "[INF] Scan completed in 1m. 2 matches found.\n", 0)
	rdb.Del(ctx, shared.StreamSecurityFindings)

	s := &Service{redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test"), rootClient: newRootClient()}
	if err := s.ProcessCDNPort(ctx, ScanTarget{Target: site.URL, DiscoveryID: "p1", OrgID: "org"}); err != nil {
		t.Fatal(err)
	}
	msgs, err := rdb.XRange(ctx, shared.StreamSecurityFindings, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want the 2 findings and no coverage", len(msgs))
	}
	for _, m := range msgs {
		var f shared.SecurityFinding
		if err := json.Unmarshal([]byte(m.Values["data"].(string)), &f); err != nil {
			t.Fatal(err)
		}
		if f.Coverage != nil || f.DiscoveryID != "p1" {
			t.Fatalf("message = %+v, want a finding of discovery p1", f)
		}
	}
}
