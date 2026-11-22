package port_discovery

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/port_discovery/services"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// fakeScanner reports the given ports open.
type fakeScanner []int

func (f fakeScanner) ScanPortsFiltered(context.Context, string, []int) []services.PortResult {
	var open []services.PortResult
	for _, p := range f {
		open = append(open, services.PortResult{Port: p, Open: true})
	}
	return open
}

// TestFindingsCarryAssetID checks against a real Redis (VULWALL_TEST_REDIS_URI) that every
// finding of a port scan carries the job's asset, and that a direct IP asset gets an IP
// finding also when no port is open, so ingestion can record the asset on the IP.
func TestFindingsCarryAssetID(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_REDIS_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	ctx := context.Background()
	streams := []string{shared.StreamIPDiscoveryResults, shared.StreamSecurityFindings}
	t.Cleanup(func() { rdb.Del(ctx, streams...); _ = rdb.Close() })

	const ip = "203.0.113.5"
	scanID := "scan-1"
	tests := []struct {
		name         string
		targetDomain string
		open         fakeScanner
		want         []string // asset_type of each finding, in order
	}{
		{"direct IP, no port open", "", nil, []string{shared.AssetTypeIP}},
		{"direct IP, ports open", "", fakeScanner{22, 443}, []string{shared.AssetTypeIP, shared.AssetTypePort, shared.AssetTypePort}},
		{"IP of a name", "a.test", fakeScanner{443}, []string{shared.AssetTypePort}},
		{"IP of a name, no port open", "a.test", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdb.Del(ctx, streams...)
			s := &Service{redis: rdb, logger: zap.NewNop(), tcpScanner: tt.open, tracer: otel.Tracer("test")}
			job := shared.IPDiscoveryJob{TraceID: "trace", ScanID: &scanID, OrgID: "org", AssetID: "asset-1", IP: ip, TargetDomain: tt.targetDomain}
			if err := s.processTCPScan(ctx, job); err != nil {
				t.Fatal(err)
			}

			msgs, err := rdb.XRange(ctx, shared.StreamIPDiscoveryResults, "-", "+").Result()
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != len(tt.want) {
				t.Fatalf("%d findings, want %d (%v)", len(msgs), len(tt.want), tt.want)
			}
			for i, m := range msgs {
				var f shared.IPDiscoveryFinding
				if err := json.Unmarshal([]byte(m.Values["data"].(string)), &f); err != nil {
					t.Fatal(err)
				}
				if f.AssetType != tt.want[i] || f.AssetID != "asset-1" || f.IP != ip || f.OrgID != "org" {
					t.Errorf("finding %d = %s %s asset_id=%q, want %s with asset_id asset-1", i, f.AssetType, f.DiscoveryID, f.AssetID, tt.want[i])
				}
				if f.AssetType == shared.AssetTypeIP && f.DiscoveryID != shared.GenerateIPID("org", ip) {
					t.Errorf("IP finding discovery_id = %s, want the IP's", f.DiscoveryID)
				}
			}

			// Coverage stays as it was: ok only when a port was open.
			n, err := rdb.XLen(ctx, shared.StreamSecurityFindings).Result()
			if err != nil {
				t.Fatal(err)
			}
			if want := int64(min(len(tt.open), 1)); n != want {
				t.Errorf("%d coverage messages, want %d", n, want)
			}
		})
	}
}
