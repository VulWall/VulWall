package certificate_scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// testNow is the fixed clock of the tests.
var testNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// selfSigned returns a certificate for www.example.com valid until notAfter, issued by a
// throwaway "Test CA".
func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             notAfter.AddDate(-1, 0, 0),
		NotAfter:              notAfter.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    notAfter.AddDate(0, -3, 0),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer serves cert on a loopback port and returns its address and a function that
// returns the SNI of the last handshake.
func tlsServer(t *testing.T, cert tls.Certificate) (addr string, sni func() string) {
	t.Helper()
	var mu sync.Mutex
	var last string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			last = hello.ServerName
			mu.Unlock()
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String(), func() string { mu.Lock(); defer mu.Unlock(); return last }
}

// recorder collects the published messages.
type recorder struct {
	mu   sync.Mutex
	msgs []shared.SecurityFinding
	err  error // returned by every publish when set
}

func (r *recorder) publish(_ context.Context, msg shared.SecurityFinding) error {
	if r.err != nil {
		return r.err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, msg)
	return nil
}

// findings and coverage split the recorded messages.
func (r *recorder) split(t *testing.T) (findings []shared.SecurityFinding, cov *shared.ScanCoverage) {
	t.Helper()
	for _, m := range r.msgs {
		if m.Coverage != nil {
			if cov != nil {
				t.Fatalf("two coverage messages")
			}
			cov = m.Coverage
			continue
		}
		findings = append(findings, m)
	}
	return findings, cov
}

func newTestService(rec *recorder, now time.Time) *Service {
	return &Service{
		logger:  zap.NewNop(),
		tracer:  otel.Tracer("test"),
		limits:  thresholds{warn: DefaultWarnDays, critical: DefaultCriticalDays},
		now:     func() time.Time { return now },
		dial:    shared.SSRFSafeDialContext(&net.Dialer{Timeout: 2 * time.Second}),
		publish: rec.publish,
	}
}

func testTarget(addr string) ScanTarget {
	scanID := "scan-1"
	return ScanTarget{Target: addr, AssetType: shared.AssetTypeSubdomain, DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}
}

// TestProcessTargetExpiry: the four certificate ages give the right finding, and coverage
// ok lists exactly the finding that was published.
func TestProcessTargetExpiry(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true") // the test server is on loopback

	for name, tc := range map[string]struct {
		notAfter    time.Time
		findingType string
		severity    string
	}{
		"expired":  {testNow.Add(-48 * time.Hour), findingTypeExpired, shared.SeverityHigh},
		"5 days":   {testNow.AddDate(0, 0, 5), findingTypeExpiring, shared.SeverityHigh},
		"20 days":  {testNow.AddDate(0, 0, 20), findingTypeExpiring, shared.SeverityMedium},
		"90 days":  {testNow.AddDate(0, 0, 90), "", ""},
		"31 days":  {testNow.AddDate(0, 0, 31), "", ""},
		"30 days":  {testNow.AddDate(0, 0, 30), findingTypeExpiring, shared.SeverityMedium},
		"7 days":   {testNow.AddDate(0, 0, 7), findingTypeExpiring, shared.SeverityHigh},
		"8 days":   {testNow.AddDate(0, 0, 8), findingTypeExpiring, shared.SeverityMedium},
		"just now": {testNow, findingTypeExpired, shared.SeverityHigh},
	} {
		t.Run(name, func(t *testing.T) {
			addr, sni := tlsServer(t, selfSigned(t, tc.notAfter))
			rec := &recorder{}
			if err := newTestService(rec, testNow).ProcessTarget(context.Background(), testTarget(addr), "www.example.com"); err != nil {
				t.Fatalf("ProcessTarget: %v", err)
			}
			if got := sni(); got != "www.example.com" {
				t.Errorf("SNI = %q, want www.example.com", got)
			}
			findings, cov := rec.split(t)
			if cov == nil || cov.Status != shared.CoverageOK || cov.Source != findingSource || cov.DiscoveryID != "d1" {
				t.Fatalf("coverage = %+v, want ok for certificate/d1", cov)
			}
			if tc.findingType == "" {
				if len(findings) != 0 || len(cov.Reported) != 0 {
					t.Fatalf("findings %+v, reported %+v: want none", findings, cov.Reported)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.FindingType != tc.findingType || f.Severity != tc.severity || f.Source != findingSource {
				t.Errorf("finding = %s/%s/%s, want %s/%s/%s", f.FindingType, f.Severity, f.Source, tc.findingType, tc.severity, findingSource)
			}
			if !strings.Contains(f.Title, addr) {
				t.Errorf("title %q does not name the host %s", f.Title, addr)
			}
			for _, want := range []string{tc.notAfter.UTC().Format("2006-01-02"), "CN=Test CA", "CN=www.example.com"} {
				if !strings.Contains(f.Description, want) {
					t.Errorf("description %q lacks %q", f.Description, want)
				}
			}
			if f.Remediation == "" {
				t.Error("no remediation")
			}
			want := shared.FindingKey{FindingType: f.FindingType, Title: f.Title}
			if len(cov.Reported) != 1 || cov.Reported[0] != want {
				t.Errorf("reported = %+v, want [%+v]", cov.Reported, want)
			}
		})
	}
}

// TestFindingKeyStable: while a certificate approaches its expiry, scans on different days
// report one finding key (the day count is only in the description), and the severity
// rises from medium to high. Once it has expired, the key changes to the expired one.
func TestFindingKeyStable(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	notAfter := testNow.AddDate(0, 0, 25)
	addr, _ := tlsServer(t, selfSigned(t, notAfter))

	type result struct {
		key      shared.FindingKey
		severity string
		desc     string
	}
	scan := func(daysLater int) result {
		rec := &recorder{}
		if err := newTestService(rec, testNow.AddDate(0, 0, daysLater)).ProcessTarget(context.Background(), testTarget(addr), ""); err != nil {
			t.Fatal(err)
		}
		findings, _ := rec.split(t)
		if len(findings) != 1 {
			t.Fatalf("day +%d: %d findings, want 1", daysLater, len(findings))
		}
		f := findings[0]
		return result{shared.FindingKey{FindingType: f.FindingType, Title: f.Title}, f.Severity, f.Description}
	}

	first, second, late, expired := scan(0), scan(1), scan(20), scan(26)
	if first.key != second.key || first.key != late.key {
		t.Errorf("keys differ across days: %+v, %+v, %+v", first.key, second.key, late.key)
	}
	if first.desc == second.desc {
		t.Error("description does not change with the day count")
	}
	if first.severity != shared.SeverityMedium || late.severity != shared.SeverityHigh {
		t.Errorf("severity %s then %s, want medium then high", first.severity, late.severity)
	}
	if expired.key == first.key || expired.key.FindingType != findingTypeExpired {
		t.Errorf("expired key = %+v, want the expired type, distinct from %+v", expired.key, first.key)
	}
}

// TestProcessTargetIncomplete: a check that did not read a certificate reports coverage
// error and no finding, so it resolves nothing.
func TestProcessTargetIncomplete(t *testing.T) {
	// A port where nothing listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	// A port that speaks plain text, not TLS.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { plain.Close() })
	go func() {
		for {
			conn, err := plain.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("220 smtp ready\r\n"))
			conn.Close()
		}
	}()

	// expired serves an expired certificate, which the check must not get to read.
	expired := func(t *testing.T) string {
		addr, _ := tlsServer(t, selfSigned(t, testNow.Add(-time.Hour)))
		return addr
	}
	for name, tc := range map[string]struct {
		allowPrivate string
		target       func(t *testing.T) ScanTarget
	}{
		"connection refused": {"true", func(*testing.T) ScanTarget { return testTarget(closedAddr) }},
		"not TLS":            {"true", func(*testing.T) ScanTarget { return testTarget(plain.Addr().String()) }},
		// The SSRF guard refuses loopback: even an expired certificate there is not read.
		"guard refuses": {"false", func(t *testing.T) ScanTarget { return testTarget(expired(t)) }},
		"unresolved": {"true", func(t *testing.T) ScanTarget {
			tg := testTarget(expired(t))
			tg.Unresolved = true
			return tg
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(config.EnvAllowPrivateTargets, tc.allowPrivate)
			rec := &recorder{}
			if err := newTestService(rec, testNow).ProcessTarget(context.Background(), tc.target(t), "www.example.com"); err != nil {
				t.Fatalf("ProcessTarget = %v, want nil (a failed check is a result)", err)
			}
			findings, cov := rec.split(t)
			if len(findings) != 0 {
				t.Errorf("findings = %+v, want none", findings)
			}
			if cov == nil || cov.Status != shared.CoverageError || cov.Error == "" || len(cov.Reported) != 0 {
				t.Fatalf("coverage = %+v, want error with a reason", cov)
			}
			t.Logf("coverage error: %s", cov.Error)
		})
	}
}

// TestProcessTargetPublishFailure: a failed publish fails the handler (the trigger is
// retried) instead of ACKing a target whose result was lost.
func TestProcessTargetPublishFailure(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	addr, _ := tlsServer(t, selfSigned(t, testNow.AddDate(0, 0, 3)))
	rec := &recorder{err: errors.New("redis down")}
	if err := newTestService(rec, testNow).ProcessTarget(context.Background(), testTarget(addr), ""); err == nil {
		t.Fatal("ProcessTarget = nil with publish failing, want the error")
	}
}

// TestProcessTargetShutdown: a check cut off by shutdown publishes nothing and returns the
// context error, so the trigger stays pending.
func TestProcessTargetShutdown(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	addr, _ := tlsServer(t, selfSigned(t, testNow.AddDate(0, 0, 3)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &recorder{}
	if err := newTestService(rec, testNow).ProcessTarget(ctx, testTarget(addr), ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessTarget = %v, want context.Canceled", err)
	}
	if len(rec.msgs) != 0 {
		t.Errorf("published %d messages after shutdown, want none", len(rec.msgs))
	}
}

func TestClip(t *testing.T) {
	if got := clip("CN=short"); got != "CN=short" {
		t.Errorf("clip(short) = %q", got)
	}
	got := clip("CN=" + strings.Repeat("é", 300))
	if len(got) > maxNameLen+3 || !strings.HasSuffix(got, "...") || !utf8.ValidString(got) {
		t.Errorf("clip(long) = %q (%d bytes), want at most %d valid bytes ending in ...", got, len(got), maxNameLen+3)
	}
}

func TestLoadThresholds(t *testing.T) {
	def := thresholds{warn: DefaultWarnDays, critical: DefaultCriticalDays}
	for name, tc := range map[string]struct {
		warn, critical string
		want           thresholds
		ok             bool
	}{
		"unset":             {"", "", def, true},
		"set":               {"45", "14", thresholds{45, 14}, true},
		"spaces":            {" 45 ", " 14 ", thresholds{45, 14}, true},
		"equal":             {"10", "10", thresholds{10, 10}, true},
		"warn not a number": {"abc", "7", def, false},
		"critical zero":     {"30", "0", def, false},
		"negative":          {"-1", "7", def, false},
		"critical above":    {"5", "7", def, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(config.EnvCertExpiryWarnDays, tc.warn)
			t.Setenv(config.EnvCertExpiryCriticalDays, tc.critical)
			got, err := loadThresholds()
			if got != tc.want || (err == nil) != tc.ok {
				t.Errorf("loadThresholds() = %+v, %v; want %+v, ok=%v", got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestDomainTarget(t *testing.T) {
	ip := "203.0.113.5"
	scanID := "s"
	f := shared.DiscoveryFinding{OrgID: "org", Host: "www.example.com", AssetType: shared.AssetTypeSubdomain, DiscoveryID: "d1", IP: &ip, ScanID: &scanID}
	got, ok := domainTarget(f)
	if !ok || got.Target != "www.example.com:443" || got.DiscoveryID != "d1" || got.Unresolved {
		t.Errorf("domainTarget = %+v, %v", got, ok)
	}
	if got := displayHost(got); got != "www.example.com" {
		t.Errorf("displayHost = %q, want the hostname", got)
	}

	noIP := f
	noIP.IP = nil
	if got, ok := domainTarget(noIP); !ok || !got.Unresolved {
		t.Errorf("no IP: %+v, %v; want an unresolved target", got, ok)
	}
	for name, mod := range map[string]func(*shared.DiscoveryFinding){
		"no org":  func(f *shared.DiscoveryFinding) { f.OrgID = "" },
		"no host": func(f *shared.DiscoveryFinding) { f.Host = "" },
		"ip":      func(f *shared.DiscoveryFinding) { f.AssetType = shared.AssetTypeIP },
	} {
		g := f
		mod(&g)
		if _, ok := domainTarget(g); ok {
			t.Errorf("%s: got a target, want none", name)
		}
	}
}

func TestPortTarget(t *testing.T) {
	f := shared.IPDiscoveryFinding{OrgID: "org", IP: "203.0.113.5", Port: 8443, AssetType: shared.AssetTypePort, DiscoveryID: "p1"}
	got, ok := portTarget(f)
	if !ok || got.Target != "203.0.113.5:8443" || got.DiscoveryID != "p1" {
		t.Errorf("portTarget = %+v, %v", got, ok)
	}
	if got := displayHost(got); got != "203.0.113.5:8443" {
		t.Errorf("displayHost = %q, want ip:port", got)
	}
	for name, mod := range map[string]func(*shared.IPDiscoveryFinding){
		"443 (checked by hostname)": func(f *shared.IPDiscoveryFinding) { f.Port = 443 },
		"not a TLS port":            func(f *shared.IPDiscoveryFinding) { f.Port = 22 },
		"CDN edge port":             func(f *shared.IPDiscoveryFinding) { f.ScanHost = "www.example.com" },
		"no org":                    func(f *shared.IPDiscoveryFinding) { f.OrgID = "" },
	} {
		g := f
		mod(&g)
		if _, ok := portTarget(g); ok {
			t.Errorf("%s: got a target, want none", name)
		}
	}
}
