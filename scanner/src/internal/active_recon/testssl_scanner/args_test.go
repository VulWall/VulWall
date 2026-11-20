package testssl_scanner

import (
	"context"
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func TestTestSSLArgsPinsValidatedIP(t *testing.T) {
	args := testSSLArgs("/tmp/out.json", "LOW", "93.184.216.34", "example.com:443")

	i := slices.Index(args, "--ip")
	if i < 0 || i+1 >= len(args) || args[i+1] != "93.184.216.34" {
		t.Fatalf("args %v: want --ip 93.184.216.34", args)
	}
	if args[len(args)-1] != "example.com:443" {
		t.Fatalf("args %v: target must stay last (hostname kept for SNI)", args)
	}
}

func TestResolveTargetIPRejectsPrivate(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")
	if _, err := resolveTargetIP(context.Background(), "127.0.0.1:443"); err == nil {
		t.Fatal("expected loopback target to be rejected")
	}

	t.Setenv(config.EnvAllowPrivateTargets, "true")
	ip, err := resolveTargetIP(context.Background(), "127.0.0.1:443")
	if err != nil || ip != "127.0.0.1" {
		t.Fatalf("resolveTargetIP() = %q, %v; want 127.0.0.1 with ALLOW_PRIVATE_TARGETS=true", ip, err)
	}
}
