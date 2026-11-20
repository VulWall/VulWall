package nuclei_scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// A domain or subdomain is scanned by its hostname (SNI and Host header reach a site behind a
// CDN or virtual host), and its findings and coverage keep the domain discovery's id.
func TestDomainScanTargetUsesHostname(t *testing.T) {
	ip := "104.20.23.154"
	scanID := "scan-1"
	got := domainScanTarget(shared.DiscoveryFinding{
		DiscoveryID: "disc-1",
		AssetType:   shared.AssetTypeSubdomain,
		TraceID:     "trace-1",
		ScanID:      &scanID,
		OrgID:       "org-1",
		Host:        "www.example.com",
		IP:          &ip,
	})
	if got.Target != "www.example.com" {
		t.Errorf("Target = %q, want the hostname", got.Target)
	}
	if got.DiscoveryID != "disc-1" || got.AssetType != shared.AssetTypeSubdomain || got.OrgID != "org-1" ||
		got.TraceID != "trace-1" || got.ScanID != &scanID {
		t.Errorf("identity fields not passed through: %+v", got)
	}
	if got.Unresolved {
		t.Error("a host with an IP is resolved")
	}
	if unresolved := domainScanTarget(shared.DiscoveryFinding{Host: "gone.example.com"}); !unresolved.Unresolved {
		t.Error("a host without an IP must be Unresolved (coverage error)")
	}
}

func TestPublicTarget(t *testing.T) {
	ctx := context.Background()
	t.Setenv(config.EnvAllowPrivateTargets, "")
	for _, target := range []string{"8.8.8.8", "https://8.8.8.8:8443"} {
		if err := publicTarget(ctx, target); err != nil {
			t.Errorf("publicTarget(%q) = %v, want nil", target, err)
		}
	}
	for _, target := range []string{"127.0.0.1", "http://10.0.0.5:8080", "localhost"} {
		if err := publicTarget(ctx, target); !errors.Is(err, shared.ErrReservedIP) {
			t.Errorf("publicTarget(%q) = %v, want ErrReservedIP", target, err)
		}
	}
	if err := publicTarget(ctx, "does-not-exist.invalid"); err == nil {
		t.Error("a name that does not resolve must fail: nothing to scan")
	}

	t.Setenv(config.EnvAllowPrivateTargets, "true")
	if err := publicTarget(ctx, "http://10.0.0.5:8080"); err != nil {
		t.Errorf("ALLOW_PRIVATE_TARGETS=true: %v, want nil", err)
	}
}

func TestScanSummary(t *testing.T) {
	log := "[INF] Targets loaded for current scan: 1\n[INF] Scan completed in 2m. 3 matches found.\n[INF] HTTP connections: 10\n"
	if got := scanSummary([]byte(log)); got != "[INF] Scan completed in 2m. 3 matches found." {
		t.Errorf("scanSummary = %q", got)
	}
	if got := scanSummary([]byte("[FTL] boom\n")); got != "" {
		t.Errorf("scanSummary without completion = %q, want empty", got)
	}
}
