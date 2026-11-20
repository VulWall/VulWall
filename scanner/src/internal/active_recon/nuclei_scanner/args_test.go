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
