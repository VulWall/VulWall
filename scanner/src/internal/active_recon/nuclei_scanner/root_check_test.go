package nuclei_scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

func TestRootURLs(t *testing.T) {
	for target, want := range map[string][]string{
		"https://203.0.113.7:8443": {"https://203.0.113.7:8443"},
		"example.com":              {"https://example.com/", "http://example.com/"},
		"203.0.113.7":              {"https://203.0.113.7/", "http://203.0.113.7/"},
	} {
		if got := rootURLs(target); !slices.Equal(got, want) {
			t.Errorf("rootURLs(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestRootBlocked(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true") // httptest listens on loopback
	cases := map[string]struct {
		h       http.HandlerFunc
		blocked bool
	}{
		"200":       {func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<html>shop</html>")) }, false},
		"404":       {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404) }, false},
		"redirect":  {func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/login", http.StatusFound) }, false},
		"403":       {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }, true},
		"429":       {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, true},
		"503":       {func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, true},
		"challenge": {func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<title>Just a moment...</title>")) }, true},
		"cf header": {func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("cf-mitigated", "challenge") }, true},
	}
	for name, c := range cases {
		srv := httptest.NewServer(c.h)
		err := rootBlocked(context.Background(), newRootClient(), srv.URL)
		srv.Close()
		if (err != nil) != c.blocked {
			t.Errorf("%s: err = %v, want blocked %v", name, err, c.blocked)
		}
	}
}

// TestRootBlockedNoHTTPAnswerAddsNothing: a port that is not HTTP gives no answer to judge;
// reachability is checked separately.
func TestRootBlockedNoHTTPAnswerAddsNothing(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		conn.Close()
	}))
	defer srv.Close()
	if err := rootBlocked(context.Background(), newRootClient(), srv.URL); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

// TestRootBlockedSendsHostname: for a hostname target the root check speaks to the site by
// name: TLS SNI and the Host header carry the hostname, as nuclei's own requests do. The dial
// itself goes through shared.SSRFSafeDialContext (newRootClient), which connects to a validated
// address; this test replaces only the dial, to reach the local test server.
func TestRootBlockedSendsHostname(t *testing.T) {
	var gotHost, gotSNI string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotSNI = r.Host, r.TLS.ServerName
		w.Write([]byte("<html>shop</html>"))
	}))
	defer srv.Close()

	client := newRootClient()
	tr := client.Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	client.Transport = tr

	if err := rootBlocked(context.Background(), client, "shop.example.com"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if gotHost != "shop.example.com" || gotSNI != "shop.example.com" {
		t.Fatalf("Host = %q, SNI = %q, want the hostname for both", gotHost, gotSNI)
	}
}
