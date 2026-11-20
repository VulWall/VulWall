package nuclei_scanner

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

// twoMatches is nuclei JSONL stdout with two matches, as the run in
// nuclei_cdn-timeout-host.stderr reported ("2 matches found").
const twoMatches = `{"template-id":"tech-detect","info":{"name":"Wappalyzer Technology Detection","severity":"low"},"matched-at":"https://example.com/"}
{"template-id":"exposed-panel","info":{"name":"Exposed Panel","severity":"medium"},"matched-at":"https://example.com/admin"}
`

// fakeNuclei puts a nuclei script on PATH that prints stdout and stderr and exits with code.
func fakeNuclei(t *testing.T, stdout, stderr string, code int) {
	t.Helper()
	dir := t.TempDir()
	out, errLog := filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")
	if err := os.WriteFile(out, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errLog, []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat '" + out + "'\ncat '" + errLog + "' >&2\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "nuclei"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func cdnTimeoutLog(t *testing.T, host string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/nuclei_cdn-timeout-host.stderr")
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "example.com", host)
}

// TestRunNucleiScanKeepsMatchesOfIncompleteRun: a run that dropped the target still returns
// the matches it found, together with the error that makes it coverage "error".
func TestRunNucleiScanKeepsMatchesOfIncompleteRun(t *testing.T) {
	s := &Service{logger: zap.NewNop()}
	for name, tc := range map[string]struct {
		stdout, stderr string
		code           int
		want           int
	}{
		"target dropped (cdn timeout)": {twoMatches, cdnTimeoutLog(t, "example.com"), 0, 2},
		"non-zero exit":                {twoMatches, "[FTL] Could not run nuclei: x\n", 1, 2},
		"unreadable line":              {twoMatches + "{cut off\n", "[INF] Scan completed in 1m. 2 matches found.\n", 0, 2},
	} {
		t.Run(name, func(t *testing.T) {
			fakeNuclei(t, tc.stdout, tc.stderr, tc.code)
			got, err := s.runNucleiScan(context.Background(), "example.com", "low")
			if err == nil {
				t.Fatal("err = nil, want the run to be incomplete")
			}
			if len(got) != tc.want {
				t.Fatalf("findings = %+v, want %d", got, tc.want)
			}
		})
	}
}

// TestProcessDiscoveryPublishesMatchesOfIncompleteRun checks against a real Redis
// (VULWALL_TEST_REDIS_URI) that an incomplete run publishes its matches, then coverage
// "error", so the matches are recorded and nothing is resolved.
func TestProcessDiscoveryPublishesMatchesOfIncompleteRun(t *testing.T) {
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

	for name, tc := range map[string]struct {
		target, stderr, wantErr string
	}{
		// nuclei dropped the target mid-run and still reported "2 matches found".
		"target dropped": {"127.0.0.1", cdnTimeoutLog(t, "127.0.0.1"), "unresponsive"},
		// A finished run, but nothing answers on the target afterwards (port 1 refuses).
		"unreachable after the run": {"http://127.0.0.1:1", "[INF] Scan completed in 1m. 2 matches found.\n", "not reachable after the run"},
	} {
		t.Run(name, func(t *testing.T) {
			fakeNuclei(t, twoMatches, tc.stderr, 0)
			rdb.Del(ctx, shared.StreamSecurityFindings)
			s := &Service{redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test")}
			scanID := "scan-1"
			target := ScanTarget{Target: tc.target, DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}

			if err := s.ProcessDiscovery(ctx, target); err != nil {
				t.Fatal(err)
			}
			msgs, err := rdb.XRange(ctx, shared.StreamSecurityFindings, "-", "+").Result()
			if err != nil {
				t.Fatal(err)
			}
			if len(msgs) != 3 {
				t.Fatalf("%d messages, want 2 findings and the coverage", len(msgs))
			}
			var got []shared.SecurityFinding
			for _, m := range msgs {
				var f shared.SecurityFinding
				if err := json.Unmarshal([]byte(m.Values["data"].(string)), &f); err != nil {
					t.Fatal(err)
				}
				got = append(got, f)
			}
			if got[0].Coverage != nil || got[1].Coverage != nil || got[0].FindingType != "tech-detect" {
				t.Fatalf("first messages = %+v, want the two findings", got[:2])
			}
			cov := got[2].Coverage
			if cov == nil || cov.Status != shared.CoverageError || len(cov.Reported) != 0 || !strings.Contains(cov.Error, tc.wantErr) {
				t.Fatalf("coverage = %+v, want error mentioning %q and nothing reported", cov, tc.wantErr)
			}
		})
	}
}
