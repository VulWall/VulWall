package domain_discovery

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// fakeEnumerator returns the given subdomains for any domain.
type fakeEnumerator []string

func (f fakeEnumerator) DiscoverSubdomains(context.Context, string) ([]string, error) {
	return f, nil
}

// TestFindingsCarryAssetID checks against a real Redis (VULWALL_TEST_REDIS_URI) that the
// root finding and every subdomain finding carry the job's asset: subfinder's names and the
// known names alike.
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
	rdb.Del(ctx, shared.StreamDomainDiscoveryResults)
	t.Cleanup(func() { rdb.Del(ctx, shared.StreamDomainDiscoveryResults); _ = rdb.Close() })

	s := &Service{
		redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test"), dnsWorkers: 2,
		subfinderClient: fakeEnumerator{"www.a.test"},
		lookupIP: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
	}
	scanID := "scan-1"
	job := shared.DiscoveryJob{TraceID: "trace", ScanID: &scanID, OrgID: "org", AssetID: "asset-1",
		Host: "a.test", KnownSubdomains: []string{"old.a.test"}}
	if err := s.ProcessJob(ctx, job); err != nil {
		t.Fatal(err)
	}

	msgs, err := rdb.XRange(ctx, shared.StreamDomainDiscoveryResults, "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, m := range msgs {
		var f shared.DiscoveryFinding
		if err := json.Unmarshal([]byte(m.Values["data"].(string)), &f); err != nil {
			t.Fatal(err)
		}
		if f.Degraded != nil {
			t.Fatalf("unexpected degraded signal: %+v", f.Degraded)
		}
		if f.AssetID != "asset-1" {
			t.Errorf("%s finding of %s: asset_id = %q, want asset-1", f.AssetType, f.Host, f.AssetID)
		}
		hosts = append(hosts, f.Host)
	}
	slices.Sort(hosts)
	if want := []string{"a.test", "old.a.test", "www.a.test"}; !slices.Equal(hosts, want) {
		t.Errorf("findings for %v, want %v", hosts, want)
	}
}
