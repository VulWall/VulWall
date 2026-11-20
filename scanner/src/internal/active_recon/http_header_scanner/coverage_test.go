package http_header_scanner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/http_header_scanner/scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// fakeScanner answers per URL prefix ("http://" or "https://").
type fakeScanner map[string]struct {
	checks []scanner.HeaderCheckResult
	err    error
}

func (f fakeScanner) Scan(_ context.Context, url string) ([]scanner.HeaderCheckResult, error) {
	proto := strings.SplitN(url, "://", 2)[0]
	r := f[proto]
	return r.checks, r.err
}

var hsts = scanner.HeaderCheckResult{HeaderName: "Strict-Transport-Security", FindingType: "missing-hsts", Title: "Missing HSTS", Severity: "medium"}

func newService(rdb *redis.Client, sc scanner.Scanner) *Service {
	return &Service{redis: rdb, logger: zap.NewNop(), scanner: sc, tracer: otel.Tracer("test")}
}

func testTarget() ScanTarget {
	scanID := "scan-1"
	return ScanTarget{Target: "www.example.com", AssetType: shared.AssetTypeSubdomain, DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}
}

// TestProcessDiscoveryReturnsPublishFailure: a publish that fails must fail the handler, so
// ConsumeStream retries the trigger instead of ACKing a target whose result was lost.
func TestProcessDiscoveryReturnsPublishFailure(t *testing.T) {
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, MaxRetries: -1})
	defer dead.Close()
	sc := fakeScanner{"http": {checks: []scanner.HeaderCheckResult{hsts}}, "https": {checks: []scanner.HeaderCheckResult{hsts}}}

	if err := newService(dead, sc).ProcessDiscovery(context.Background(), testTarget()); err == nil {
		t.Fatal("ProcessDiscovery = nil with Redis down, want the publish error")
	}
}

// TestProcessDiscoveryCoverage checks the coverage message against a real Redis
// (VULWALL_TEST_REDIS_URI): ok with the reported keys only when both protocols answered.
func TestProcessDiscoveryCoverage(t *testing.T) {
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

	for name, tc := range map[string]struct {
		sc     fakeScanner
		status string
	}{
		"both answered":     {fakeScanner{"http": {checks: []scanner.HeaderCheckResult{hsts}}, "https": {}}, shared.CoverageOK},
		"https timed out":   {fakeScanner{"http": {}, "https": {err: context.DeadlineExceeded}}, shared.CoverageError},
		"https TLS failure": {fakeScanner{"http": {}, "https": {err: errors.New("tls: handshake failure")}}, shared.CoverageError},
	} {
		t.Run(name, func(t *testing.T) {
			rdb.Del(ctx, shared.StreamSecurityFindings)
			if err := newService(rdb, tc.sc).ProcessDiscovery(ctx, testTarget()); err != nil {
				t.Fatal(err)
			}
			msgs, err := rdb.XRange(ctx, shared.StreamSecurityFindings, "-", "+").Result()
			if err != nil || len(msgs) == 0 {
				t.Fatalf("messages = %v, %v", msgs, err)
			}
			var last shared.SecurityFinding
			if err := json.Unmarshal([]byte(msgs[len(msgs)-1].Values["data"].(string)), &last); err != nil {
				t.Fatal(err)
			}
			if last.Coverage == nil || last.Coverage.Status != tc.status {
				t.Fatalf("last message coverage = %+v, want status %s (coverage comes after the findings)", last.Coverage, tc.status)
			}
			if tc.status == shared.CoverageOK && (len(last.Coverage.Reported) != 1 || last.Coverage.Reported[0].FindingType != "missing-hsts") {
				t.Fatalf("reported = %+v, want the one finding", last.Coverage.Reported)
			}
		})
	}
}
