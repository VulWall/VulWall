package testssl_scanner

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// TestProcessDiscoveryChecksReachabilityOfScannedIP checks against a real Redis
// (VULWALL_TEST_REDIS_URI) that the reachability check after the run dials the IP
// testssl.sh scanned (--ip), not any address of the host. localhost resolves to two
// loopback addresses; only the one testssl.sh did not scan listens, so the run is no
// evidence: coverage "error".
func TestProcessDiscoveryChecksReachabilityOfScannedIP(t *testing.T) {
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

	ips, err := shared.ResolvePublicIPs(ctx, "localhost")
	if err != nil || len(ips) < 2 {
		t.Skipf("localhost resolves to %v (%v); need two addresses", ips, err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ips[1].String(), "0"))
	if err != nil {
		t.Skipf("listen on %s: %v", ips[1], err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if conn, err := net.Dial("tcp", net.JoinHostPort(ips[0].String(), port)); err == nil {
		conn.Close()
		t.Skipf("port %s also listens on the scanned address %s", port, ips[0])
	}

	fakeTestSSL(t, string(readTestdata(t, "testssl_ok.json")), 0)
	rdb.Del(ctx, shared.StreamSecurityFindings)
	s := &Service{redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test")}
	scanID := "scan-1"
	target := ScanTarget{Target: net.JoinHostPort("localhost", port), DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}
	if err := s.ProcessDiscovery(ctx, target); err != nil {
		t.Fatal(err)
	}

	msgs, err := rdb.XRange(ctx, shared.StreamSecurityFindings, "-", "+").Result()
	if err != nil || len(msgs) == 0 {
		t.Fatalf("messages = %d, %v; want the coverage", len(msgs), err)
	}
	var last shared.SecurityFinding
	if json.Unmarshal([]byte(msgs[len(msgs)-1].Values["data"].(string)), &last) != nil {
		t.Fatal("unreadable message")
	}
	if c := last.Coverage; c == nil || c.Status != shared.CoverageError || !strings.Contains(c.Error, "not reachable after the run") {
		t.Fatalf("coverage = %+v, want error 'not reachable after the run'", c)
	}
}
