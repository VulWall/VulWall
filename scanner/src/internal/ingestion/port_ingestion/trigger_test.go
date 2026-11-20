package port_ingestion

import (
	"strings"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

func TestPortTrigger(t *testing.T) {
	cases := []struct {
		name         string
		ip           string
		port         int
		targetDomain string
		wantSkip     string // reason prefix; "" = trigger published
		wantScanHost string
	}{
		// example.com resolves to Cloudflare: 80/443 are left to the hostname scan.
		{"cloudflare 443", "104.20.23.154", 443, "example.com", "cdn_edge_web_port:Cloudflare", ""},
		{"cloudflare 80", "104.20.23.154", 80, "example.com", "cdn_edge_web_port:Cloudflare", ""},
		{"cloudflare ipv6 443", "2606:4700::6812:1", 443, "example.com", "cdn_edge_web_port:Cloudflare", ""},
		{"fastly 80", "151.101.1.1", 80, "shop.example.org", "cdn_edge_web_port:Fastly", ""},
		// A non-standard port of a CDN edge is scanned by the name that resolved to it.
		{"cloudflare 8443 by name", "104.20.23.154", 8443, "example.com", "", "example.com"},
		{"cloudflare 8080 by name", "172.66.147.243", 8080, "www.example.com", "", "www.example.com"},
		// A CDN address added as a direct IP asset has no name to ask for.
		{"cloudflare direct asset", "172.66.147.243", 8443, "", "cdn_edge_no_name:Cloudflare", ""},
		// Customer servers keep the IP scan on every port, also 80/443 of a name's address.
		{"own server 80 from a name", "203.0.113.10", 80, "shop.example.org", "", ""},
		{"own server 443 from a name", "203.0.113.10", 443, "shop.example.org", "", ""},
		{"own server 8443 from a name", "203.0.113.10", 8443, "shop.example.org", "", ""},
		{"own server direct asset", "203.0.113.10", 443, "", "", ""},
		// General cloud compute is customer hardware, not a CDN edge.
		{"aws ec2", "3.80.0.1", 443, "app.example.org", "", ""},
		{"gcp compute", "34.120.0.1", 80, "app.example.org", "", ""},
		{"azure vm", "20.50.0.1", 443, "app.example.org", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := shared.IPDiscoveryFinding{IP: tc.ip, Port: tc.port, TargetDomain: tc.targetDomain}
			trigger, reason := portTrigger(in)
			if tc.wantSkip != "" {
				if !strings.HasPrefix(reason, tc.wantSkip) {
					t.Fatalf("reason = %q, want %q", reason, tc.wantSkip)
				}
				return
			}
			if reason != "" {
				t.Fatalf("reason = %q, want the trigger published", reason)
			}
			if trigger.ScanHost != tc.wantScanHost || trigger.IP != tc.ip || trigger.Port != tc.port {
				t.Fatalf("trigger = %+v, want ScanHost %q on %s:%d", trigger, tc.wantScanHost, tc.ip, tc.port)
			}
		})
	}
}
