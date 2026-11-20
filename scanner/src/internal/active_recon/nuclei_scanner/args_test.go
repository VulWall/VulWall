package nuclei_scanner

import (
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func TestNucleiArgsRestrictLocalNetwork(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")
	if args := nucleiArgs("https://example.com", "low"); !slices.Contains(args, "-lna") {
		t.Fatalf("args %v: want -lna by default", args)
	}

	t.Setenv(config.EnvAllowPrivateTargets, "true")
	if args := nucleiArgs("https://example.com", "low"); slices.Contains(args, "-lna") {
		t.Fatalf("args %v: -lna must be omitted with ALLOW_PRIVATE_TARGETS=true", args)
	}
}

func TestNucleiArgsRateLimit(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		ok    bool
	}{
		{"unset", "", "50", true},
		{"set", "30", "30", true},
		{"spaces", " 30 ", "30", true},
		{"zero", "0", "50", false},
		{"negative", "-5", "50", false},
		{"not a number", "abc", "50", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(config.EnvNucleiRateLimit, tt.value)
			args := nucleiArgs("https://example.com", "low")
			i := slices.Index(args, "-rl")
			if i < 0 || i+1 >= len(args) || args[i+1] != tt.want {
				t.Fatalf("args %v: want -rl %s", args, tt.want)
			}
			if _, ok := rateLimit(); ok != tt.ok {
				t.Fatalf("rateLimit() ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}
