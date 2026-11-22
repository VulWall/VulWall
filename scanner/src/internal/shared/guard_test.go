package shared

import (
	"errors"
	"net"
	"testing"
)

// IPv6 forms that reach an IPv4 address, and the IPv6 special-use ranges the guard refuses.
var embeddedIPv4Cases = []struct {
	name     string
	ip       string
	reserved bool
}{
	{"IPv4-compatible loopback", "::7f00:1", true},
	{"IPv4-compatible public (deprecated form, refused)", "::808:808", true},
	{"IPv4-mapped public", "::ffff:8.8.8.8", false},
	{"discard-only", "100::1", true},
	{"documentation", "2001:db8::1", true},

	{"NAT64 well-known, loopback", "64:ff9b::7f00:1", true},
	{"NAT64 well-known, metadata", "64:ff9b::a9fe:a9fe", true},
	{"NAT64 well-known, RFC1918", "64:ff9b::a00:1", true},
	{"NAT64 well-known, public", "64:ff9b::808:808", false},
	{"NAT64 local-use, any embedded address", "64:ff9b:1::808:808", true},

	{"6to4, loopback", "2002:7f00:1::1", true},
	{"6to4, RFC1918", "2002:a00:1::1", true},
	{"6to4, public", "2002:808:808::1", false},

	// Teredo: server in bits 32-63, client inverted in the last 32 bits.
	{"Teredo, public server and client", "2001:0:808:808::fefe:fefe", false},
	{"Teredo, RFC1918 client", "2001:0:808:808::f5ff:fffe", true},
	{"Teredo, loopback server", "2001:0:7f00:1::fefe:fefe", true},

	{"public IPv6 next to Teredo", "2001:4860:4860::8888", false},
}

func TestIsPrivateIP_EmbeddedIPv4(t *testing.T) {
	t.Parallel()
	for _, tc := range embeddedIPv4Cases {
		got, err := IsPrivateIP(tc.ip)
		if err != nil || got != tc.reserved {
			t.Errorf("%s: IsPrivateIP(%q) = %v, %v; want %v", tc.name, tc.ip, got, err, tc.reserved)
		}
	}
}

func TestCheckPublicIPs_EmbeddedIPv4(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "false")
	for _, tc := range embeddedIPv4Cases {
		err := CheckPublicIPs([]net.IP{net.ParseIP(tc.ip)})
		if got := errors.Is(err, ErrReservedIP); got != tc.reserved {
			t.Errorf("%s: CheckPublicIPs(%q) = %v; want refused %v", tc.name, tc.ip, err, tc.reserved)
		}
	}
}

func TestCheckPublicIPs_EmbeddedIPv4AllowPrivateTargets(t *testing.T) {
	t.Setenv("ALLOW_PRIVATE_TARGETS", "true")
	for _, tc := range embeddedIPv4Cases {
		if err := CheckPublicIPs([]net.IP{net.ParseIP(tc.ip)}); err != nil {
			t.Errorf("%s: CheckPublicIPs(%q) = %v with ALLOW_PRIVATE_TARGETS=true, want nil", tc.name, tc.ip, err)
		}
	}
}
