package scan_coordinator

import (
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// TestPartitionByDegraded checks that only the findings under a degraded root domain stay
// open, and that the other assets of the same scan are reconciled normally.
func TestPartitionByDegraded(t *testing.T) {
	t.Parallel()

	discoveries := map[string]discoveryRef{
		"d-dead":      {ID: "d-dead", AssetType: shared.AssetTypeDomain, Domain: "dead.example"},
		"s-dead":      {ID: "s-dead", AssetType: shared.AssetTypeSubdomain, Subdomain: "www.Dead.Example"},
		"d-live":      {ID: "d-live", AssetType: shared.AssetTypeDomain, Domain: "live.example"},
		"s-live":      {ID: "s-live", AssetType: shared.AssetTypeSubdomain, Subdomain: "api.live.example"},
		"s-lookalike": {ID: "s-lookalike", AssetType: shared.AssetTypeSubdomain, Subdomain: "notdead.example"},
		"ip-dead":     {ID: "ip-dead", AssetType: shared.AssetTypeIP, IP: "203.0.113.7"},
		"port-dead":   {ID: "port-dead", AssetType: shared.AssetTypePort, IP: "203.0.113.7"},
		"port-live":   {ID: "port-live", AssetType: shared.AssetTypePort, IP: "198.51.100.1"},
		"ip-noaddr":   {ID: "ip-noaddr", AssetType: shared.AssetTypeIP},
		"odd":         {ID: "odd", AssetType: "certificate"},
	}
	candidates := []findingRef{
		{"f-dead-root", "d-dead"},
		{"f-dead-sub", "s-dead"},
		{"f-live-root", "d-live"},
		{"f-live-sub", "s-live"},
		{"f-lookalike", "s-lookalike"},
		{"f-dead-ip", "ip-dead"},
		{"f-dead-port", "port-dead"},
		{"f-live-port", "port-live"},
		{"f-no-ip", "ip-noaddr"},
		{"f-unknown-type", "odd"},
		{"f-missing-discovery", "gone"},
	}
	ips := map[string]bool{"203.0.113.7": true}

	resolve, unchecked := partitionByDegraded(candidates, discoveries, []string{"dead.example"}, ips)

	wantResolve := []string{"f-live-root", "f-live-sub", "f-lookalike", "f-live-port"}
	wantUnchecked := []string{"f-dead-root", "f-dead-sub", "f-dead-ip", "f-dead-port",
		"f-no-ip", "f-unknown-type", "f-missing-discovery"}
	if !slices.Equal(resolve, wantResolve) {
		t.Errorf("resolve = %v, want %v", resolve, wantResolve)
	}
	if !slices.Equal(unchecked, wantUnchecked) {
		t.Errorf("unchecked = %v, want %v", unchecked, wantUnchecked)
	}
}

// TestPartitionByDegraded_NoDegradedDomain: with nothing degraded every mapped finding is
// resolved (a root that was degraded before and is healthy now is no longer protected).
func TestPartitionByDegraded_NoDegradedDomain(t *testing.T) {
	t.Parallel()

	discoveries := map[string]discoveryRef{
		"d": {ID: "d", AssetType: shared.AssetTypeDomain, Domain: "dead.example"},
	}
	resolve, unchecked := partitionByDegraded([]findingRef{{"f", "d"}}, discoveries, nil, nil)
	if !slices.Equal(resolve, []string{"f"}) || len(unchecked) != 0 {
		t.Fatalf("resolve = %v, unchecked = %v; want [f], []", resolve, unchecked)
	}
}

func TestDegradedDomains(t *testing.T) {
	t.Parallel()

	got := degradedDomains([]shared.DegradedAsset{
		{AssetID: "a1", Domain: "Dead.Example.", Reason: shared.ScanDegradedRootNXDOMAIN},
		{AssetID: "a1", Domain: "dead.example", Reason: shared.ScanDegradedDNSFailures},
		{AssetID: "a2", Domain: "other.example", Reason: shared.ScanDegradedSubdomainEnumFailed},
		{Domain: ""},
	})
	if want := []string{"dead.example", "other.example"}; !slices.Equal(got, want) {
		t.Fatalf("degradedDomains = %v, want %v", got, want)
	}
}
