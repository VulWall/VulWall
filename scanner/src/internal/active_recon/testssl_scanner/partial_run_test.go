package testssl_scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

const breach = `{
                                "id"           : "BREACH",
                                "severity"     : "LOW",
                                "cwe"          : "CWE-310",
                                "finding"      : "potentially VULNERABLE, uses gzip HTTP compression"
                           }`

// withBreach is testssl_ok.json with its one finding (LUCKY13, which an override drops to
// info and so is never published) replaced by BREACH (LOW, published).
func withBreach(t *testing.T) string {
	t.Helper()
	ok := string(readTestdata(t, "testssl_ok.json"))
	start := strings.Index(ok, `{
                                "id"           : "LUCKY13"`)
	end := strings.Index(ok[start:], "}") + start + 1
	if start < 0 || end <= start {
		t.Fatal("testdata changed: no LUCKY13 entry")
	}
	return ok[:start] + breach + ok[end:]
}

// midrunWithBreach is testssl_midrun.json (fatal exit, "Scan interrupted") with BREACH found
// before the scanProblem entry.
func midrunWithBreach(t *testing.T) string {
	t.Helper()
	mid := string(readTestdata(t, "testssl_midrun.json"))
	at := strings.Index(mid, `{
                                "id"           : "scanProblem"`)
	if at < 0 {
		t.Fatal("testdata changed: no scanProblem entry")
	}
	return mid[:at] + breach + ",\n" + mid[at:]
}

// cutAfterBreach is withBreach cut off right after the BREACH entry, as a killed run leaves it.
func cutAfterBreach(t *testing.T) string {
	t.Helper()
	full := withBreach(t)
	return full[:strings.Index(full, breach)+len(breach)]
}

func TestParseTestSSLOutputKeepsFindingsOfIncompleteRun(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	for name, tc := range map[string]struct {
		data    string
		wantErr bool
	}{
		"complete":                  {withBreach(t), false},
		"scan interrupted (string)": {midrunWithBreach(t), false},
		"cut off after a finding":   {cutAfterBreach(t), true},
	} {
		got, err := s.parseTestSSLOutput([]byte(tc.data))
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, want error %v", name, err, tc.wantErr)
		}
		if len(got) != 1 || got[0].ID != "BREACH" {
			t.Errorf("%s: findings = %+v, want BREACH", name, got)
		}
	}

	// The real outputs: the healthy run has LUCKY13 (LOW); the others no security issue.
	got, err := s.parseTestSSLOutput(readTestdata(t, "testssl_ok.json"))
	if err != nil || len(got) != 1 || got[0].ID != "LUCKY13" {
		t.Fatalf("testssl_ok.json = %+v, %v; want LUCKY13", got, err)
	}
	for _, f := range []string{"testssl_midrun.json", "testssl_notls.json", "testssl_refused.json"} {
		if got, err := s.parseTestSSLOutput(readTestdata(t, f)); err != nil || len(got) != 0 {
			t.Errorf("%s = %+v, %v; want no findings and no error", f, got, err)
		}
	}
}

// fakeTestSSL puts a testssl.sh script on PATH that writes json to the --jsonfile-pretty path
// (its second argument) and exits with code.
func fakeTestSSL(t *testing.T, json string, code int) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "out.json")
	if err := os.WriteFile(src, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncp '" + src + "' \"$2\"\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "testssl.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunTestSSLScanKeepsFindingsOfIncompleteRun(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	s := &Service{logger: zap.NewNop()}
	for name, tc := range map[string]struct {
		json string
		code int
	}{
		"one check could not run": {withBreach(t), 1},
		"stopped mid-run":         {midrunWithBreach(t), 246},
		"cut off":                 {cutAfterBreach(t), 0},
	} {
		t.Run(name, func(t *testing.T) {
			fakeTestSSL(t, tc.json, tc.code)
			got, err := s.runTestSSLScan(context.Background(), "127.0.0.1:443", "LOW")
			if err == nil {
				t.Fatal("err = nil, want the run to be incomplete")
			}
			if len(got) != 1 || got[0].ID != "BREACH" {
				t.Fatalf("findings = %+v, want BREACH", got)
			}
		})
	}
}

// TestProcessDiscoveryPublishesFindingsOfIncompleteRun checks against a real Redis
// (VULWALL_TEST_REDIS_URI) that an incomplete run publishes its findings, then coverage
// "error", so they are recorded and nothing is resolved.
func TestProcessDiscoveryPublishesFindingsOfIncompleteRun(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_REDIS_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	ctx := context.Background()
	t.Setenv(config.EnvAllowPrivateTargets, "true")
	fakeTestSSL(t, withBreach(t), 1)
	rdb.Del(ctx, shared.StreamSecurityFindings)

	s := &Service{redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test")}
	scanID := "scan-1"
	if err := s.ProcessDiscovery(ctx, ScanTarget{Target: "127.0.0.1:443", DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}); err != nil {
		t.Fatal(err)
	}
	msgs, err := rdb.XRange(ctx, shared.StreamSecurityFindings, "-", "+").Result()
	if err != nil || len(msgs) != 2 {
		t.Fatalf("messages = %d, %v; want the finding and the coverage", len(msgs), err)
	}
	var first, last shared.SecurityFinding
	if json.Unmarshal([]byte(msgs[0].Values["data"].(string)), &first) != nil ||
		json.Unmarshal([]byte(msgs[1].Values["data"].(string)), &last) != nil {
		t.Fatal("unreadable message")
	}
	if first.Coverage != nil || first.FindingType != "BREACH" {
		t.Fatalf("first message = %+v, want the BREACH finding", first)
	}
	if c := last.Coverage; c == nil || c.Status != shared.CoverageError || len(c.Reported) != 0 || !strings.Contains(c.Error, "could not run 1") {
		t.Fatalf("coverage = %+v, want error 'could not run 1' and nothing reported", c)
	}
}
