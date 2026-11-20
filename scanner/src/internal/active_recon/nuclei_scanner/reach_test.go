package nuclei_scanner

import (
	"slices"
	"testing"
)

func TestReachAddrs(t *testing.T) {
	for target, want := range map[string][]string{
		"https://203.0.113.7:8443": {"203.0.113.7:8443"},
		"http://203.0.113.7:80":    {"203.0.113.7:80"},
		"https://example.com":      {"example.com:443"},
		"203.0.113.7":              {"203.0.113.7:443", "203.0.113.7:80"},
		"example.com":              {"example.com:443", "example.com:80"},
	} {
		if got := reachAddrs(target); !slices.Equal(got, want) {
			t.Errorf("reachAddrs(%q) = %v, want %v", target, got, want)
		}
	}
}
