package js_dependency_scanner

import (
	"context"
	"os"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/js_dependency_scanner/scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// TestPublishUniqueVulnerabilitiesKeysByTypeAndTitle (VULWALL_TEST_REDIS_URI): one component,
// version and CVE with two advisories (two titles) are two findings for ingestion; the same
// advisory on http and https is one.
func TestPublishUniqueVulnerabilitiesKeysByTypeAndTitle(t *testing.T) {
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
	rdb.Del(ctx, shared.StreamSecurityFindings)

	s := &Service{redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test")}
	scanID := "scan-1"
	target := ScanTarget{Target: "example.com", DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}
	a := scanner.ProcessedVulnerability{Component: "jquery", Version: "1.8.0", CVEs: []string{"CVE-2020-11022"}, Summary: "XSS in htmlPrefilter"}
	b := scanner.ProcessedVulnerability{Component: "jquery", Version: "1.8.0", CVEs: []string{"CVE-2020-11022"}, Summary: "XSS via option elements"}
	results := []protocolScanResult{
		{protocol: "http", url: "http://example.com", vulnerabilities: []scanner.ProcessedVulnerability{a}},
		{protocol: "https", url: "https://example.com", vulnerabilities: []scanner.ProcessedVulnerability{a, b}},
	}
	reported, err := s.publishUniqueVulnerabilities(ctx, results, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(reported) != 2 {
		t.Fatalf("reported = %+v, want two advisories once each", reported)
	}
}
