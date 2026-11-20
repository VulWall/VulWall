package port_ingestion

import (
	"strings"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

func TestPortTriggerSkipReason(t *testing.T) {
	cases := []struct {
		name         string
		ip           string
		port         int
		targetDomain string
		wantPrefix   string // "" = trigger published
	}{
		// example.com resolves to Cloudflare: every port of it is skipped, also with no name.
		{"cloudflare 443 from a name", "104.20.23.154", 443, "example.com", "cdn_edge:Cloudflare"},
		{"cloudflare 8443 from a name", "104.20.23.154", 8443, "example.com", "cdn_edge:Cloudflare"},
		{"cloudflare direct asset", "172.66.147.243", 2083, "", "cdn_edge:Cloudflare"},
		{"cloudflare ipv6", "2606:4700::6812:1", 80, "", "cdn_edge:Cloudflare"},
		{"fastly", "151.101.1.1", 80, "", "cdn_edge:Fastly"},
		// A customer's own server (not in any CDN range).
		{"own server 80 from a name", "203.0.113.10", 80, "shop.example.org", "hostname_scanned:shop.example.org"},
		{"own server 443 from a name", "203.0.113.10", 443, "shop.example.org", "hostname_scanned:shop.example.org"},
		{"own server unusual port from a name", "203.0.113.10", 8443, "shop.example.org", ""},
		{"own server 80 as direct asset", "203.0.113.10", 80, "", ""},
		{"own server 443 as direct asset", "203.0.113.10", 443, "", ""},
		// AWS compute (EC2 us-east-1) is customer hardware, not CloudFront.
		{"ec2", "3.80.0.1", 8080, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := portTriggerSkipReason(shared.IPDiscoveryFinding{IP: tc.ip, Port: tc.port, TargetDomain: tc.targetDomain})
			if tc.wantPrefix == "" {
				if got != "" {
					t.Fatalf("reason = %q, want the trigger published", got)
				}
				return
			}
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("reason = %q, want %q", got, tc.wantPrefix)
			}
		})
	}
}
