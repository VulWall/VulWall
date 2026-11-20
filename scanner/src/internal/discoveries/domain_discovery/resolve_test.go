package domain_discovery

import (
	"net"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func parseIPs(ss ...string) []net.IP {
	ips := make([]net.IP, 0, len(ss))
	for _, s := range ss {
		ips = append(ips, net.ParseIP(s))
	}
	return ips
}

func TestSelectPublicIP(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")

	tests := []struct {
		name    string
		ips     []net.IP
		want    string
		wantErr bool
	}{
		{"prefers first ipv4", parseIPs("2606:4700:4700::1111", "93.184.216.34"), "93.184.216.34", false},
		{"ipv6 only", parseIPs("2606:4700:4700::1111"), "2606:4700:4700::1111", false},
		{"public and private answers are rejected", parseIPs("93.184.216.34", "192.168.1.10"), "", true},
		{"private ipv6 answer is rejected", parseIPs("93.184.216.34", "fe80::1"), "", true},
		{"no answers", nil, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectPublicIP(tt.ips)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("selectPublicIP() = %q, %v; want %q, wantErr %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestSelectPublicIP_AllowPrivateTargets(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	got, err := selectPublicIP(parseIPs("10.0.0.5"))
	if err != nil || got != "10.0.0.5" {
		t.Fatalf("selectPublicIP() = %q, %v; want 10.0.0.5", got, err)
	}
}
