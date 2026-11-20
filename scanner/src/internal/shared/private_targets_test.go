package shared

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func TestCheckPublicIPs_RejectsAnyPrivateAnswer(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")

	tests := []struct {
		name    string
		ips     []string
		wantErr bool
	}{
		{"all public", []string{"93.184.216.34", "2606:4700:4700::1111"}, false},
		{"public then private", []string{"93.184.216.34", "10.0.0.5"}, true},
		{"private then public", []string{"127.0.0.1", "93.184.216.34"}, true},
		{"public v4 and private v6", []string{"93.184.216.34", "fc00::1"}, true},
		{"ipv4-mapped metadata", []string{"::ffff:169.254.169.254"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := make([]net.IP, 0, len(tt.ips))
			for _, s := range tt.ips {
				ips = append(ips, net.ParseIP(s))
			}
			err := CheckPublicIPs(ips)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckPublicIPs(%v) err = %v, wantErr %v", tt.ips, err, tt.wantErr)
			}
		})
	}
}

func TestCheckPublicIPs_AllowPrivateTargets(t *testing.T) {
	ips := []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}

	t.Setenv(config.EnvAllowPrivateTargets, "false")
	if PrivateTargetsAllowed() {
		t.Fatal("PrivateTargetsAllowed() = true with ALLOW_PRIVATE_TARGETS=false")
	}
	if err := CheckPublicIPs(ips); err == nil {
		t.Fatal("expected rejection with ALLOW_PRIVATE_TARGETS=false")
	}

	t.Setenv(config.EnvAllowPrivateTargets, "true")
	if !PrivateTargetsAllowed() {
		t.Fatal("PrivateTargetsAllowed() = false with ALLOW_PRIVATE_TARGETS=true")
	}
	if err := CheckPublicIPs(ips); err != nil {
		t.Fatalf("expected no rejection with ALLOW_PRIVATE_TARGETS=true, got %v", err)
	}
}

func TestResolvePublicIPs_NumericHost(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")
	if _, err := ResolvePublicIPs(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("expected loopback to be rejected")
	}
	ips, err := ResolvePublicIPs(context.Background(), "93.184.216.34")
	if err != nil || len(ips) != 1 {
		t.Fatalf("public numeric host: ips=%v err=%v", ips, err)
	}
}

// With ALLOW_PRIVATE_TARGETS=true the dialer reaches a loopback server that
// it refuses by default.
func TestSSRFSafeDialContext_AllowPrivateTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	dial := SSRFSafeDialContext(&net.Dialer{})
	addr := srv.Listener.Addr().String()

	t.Setenv(config.EnvAllowPrivateTargets, "")
	if conn, err := dial(context.Background(), "tcp", addr); err == nil {
		conn.Close()
		t.Fatal("expected loopback dial to be refused by default")
	}

	t.Setenv(config.EnvAllowPrivateTargets, "true")
	conn, err := dial(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("expected loopback dial to succeed with ALLOW_PRIVATE_TARGETS=true: %v", err)
	}
	conn.Close()
}
