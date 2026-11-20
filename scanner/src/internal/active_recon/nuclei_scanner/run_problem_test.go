package nuclei_scanner

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

// The testdata files are real nuclei v3.11.1 stderr logs (-j -nc, no -silent) from the scanner
// image against local test servers.
func TestRunProblemOnRealLogs(t *testing.T) {
	cases := []struct {
		name, target, file string
		complete           bool
	}{
		// Healthy nginx: completed; the only skip is for :4040, which a template probes.
		{"healthy", "http://172.20.0.3", "nuclei_ok-ip.stderr", true},
		// 403 on every request: nuclei logs nothing about it (rootBlocked covers it).
		{"403 everywhere", "http://172.20.0.4", "nuclei_forbidden-ip.stderr", true},
		// Server stopped 20 s into the run: "Skipped 172.20.0.3:80 ... unresponsive 30 times", exit 0.
		{"stopped mid-run", "http://172.20.0.3", "nuclei_mid-nosilent.stderr", false},
		// Nothing listening: "Skipped vwres-http:8080 ... unresponsive permanently", exit 0.
		{"refused", "http://vwres-http:8080", "nuclei_refused-nosilent.stderr", false},
		// The same log for a bare host: its own addresses are :443 and :80.
		{"healthy bare host", "172.20.0.3", "nuclei_ok-ip.stderr", true},
		{"stopped mid-run bare host", "172.20.0.3", "nuclei_mid-nosilent.stderr", false},
		// Hostname targets (domain triggers), nuclei v3.11.1. nuclei logs the name, not the IP:
		// "Skipped <host>:<port>".
		// Healthy nginx on port 80 only, scanned by name: completed; no skip of :443 although
		// nothing listens there (httpx picked http), only the template probe of :4040.
		{"healthy hostname", "shop.vwnh.test", "nuclei_ok-host.stderr", true},
		// example.com behind Cloudflare: connections timed out under scan load, nuclei dropped
		// "example.com:443" and still reported "Scan completed ... 2 matches found".
		{"cdn timeout hostname", "example.com", "nuclei_cdn-timeout-host.stderr", false},
		// A name whose address never answers: "Skipped 1.2.3.4.sslip.io:80", httpx found 0 URLs.
		{"dead hostname", "1.2.3.4.sslip.io", "nuclei_dead-host.stderr", false},
	}
	for _, c := range cases {
		log, err := os.ReadFile("testdata/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		err = runProblem(c.target, log)
		if (err == nil) != c.complete {
			t.Errorf("%s: err = %v, want complete %v", c.name, err, c.complete)
		}
	}
}

func TestRunProblemNeedsCompletionAndNoFatal(t *testing.T) {
	for name, log := range map[string]string{
		"no completion line": "[INF] Templates loaded for current scan: 6566\n",
		"empty":              "",
		"fatal":              "[INF] Scan completed in 177µs. No results found.\n[FTL] Could not run nuclei: no templates provided for scan\n",
	} {
		if err := runProblem("example.com", []byte(log)); err == nil {
			t.Errorf("%s: complete, want an error", name)
		}
	}
	ok := "[ERR] Could not read nuclei-ignore file: x\n[WRN] Found 262 templates with runtime error\n[INF] Scan completed in 1m. 0 matches found.\n"
	if err := runProblem("example.com", []byte(ok)); err != nil {
		t.Fatalf("harmless ERR/WRN lines: %v, want nil", err)
	}
	other := "[INF] Skipped example.com:4040 from target list as found unresponsive permanently\n[INF] Scan completed in 1m. 0 matches found.\n"
	if err := runProblem("example.com", []byte(other)); err != nil {
		t.Fatalf("skip of another port: %v, want nil", err)
	}
}

func TestParseNucleiOutput(t *testing.T) {
	out := `{"template-id":"waf-detect","info":{"name":"WAF Detection","severity":"info"},"matched-at":"http://x/"}` + "\n\n" +
		`{"template-id":"tech","info":{"name":"Tech","severity":"info"}}` + "\n"
	got, err := parseNucleiOutput([]byte(out))
	if err != nil || len(got) != 2 || got[0].TemplateID != "waf-detect" {
		t.Fatalf("parse = %+v, %v", got, err)
	}
	got, err = parseNucleiOutput([]byte(out + "{cut off"))
	if err == nil {
		t.Fatal("a broken line must fail the run: it may be a lost finding")
	}
	if len(got) != 2 {
		t.Fatalf("parse with a broken line = %+v, want the 2 lines that parse", got)
	}
}

func TestNucleiArgsKeepTheLog(t *testing.T) {
	t.Setenv(config.EnvAllowPrivateTargets, "")
	args := nucleiArgs("https://example.com", "low")
	if slices.Contains(args, "-silent") {
		t.Fatalf("args %v: -silent hides the log runProblem reads", args)
	}
	for _, want := range []string{"-nc", "-duc", "-j"} {
		if !slices.Contains(args, want) {
			t.Errorf("args %v: want %s", args, want)
		}
	}
	if !strings.Contains(strings.Join(args, " "), "-severity low") {
		t.Errorf("args %v: want -severity low", args)
	}
}
