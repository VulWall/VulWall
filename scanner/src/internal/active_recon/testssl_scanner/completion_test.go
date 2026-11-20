package testssl_scanner

import (
	"os"
	"strings"
	"testing"
)

// The testdata files are real testssl.sh 3.2.5 output (--jsonfile-pretty, -U --severity LOW)
// from the scanner image against local test servers.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunCompleteOnRealOutput(t *testing.T) {
	cases := []struct {
		name     string
		exit     int
		file     string
		complete bool
		wantErr  string
	}{
		// Healthy TLS server: exit 0, one LOW finding, "scanTime": 32.
		{"healthy server", 0, "testssl_ok.json", true, ""},
		// Nothing listening: exit 246 (ERR_CONNECT), scanProblem FATAL, "Scan interrupted".
		{"connection refused", 246, "testssl_refused.json", false, "fatal exit code 246"},
		// Plain HTTP port: testssl reaches the end (numeric scanTime) but 9 checks could not run.
		{"not TLS", 9, "testssl_notls.json", false, "could not run 9"},
		// Server stopped mid-run: exit 246, "repeated TCP connect problems, giving up".
		{"stopped mid-run", 246, "testssl_midrun.json", false, "giving up"},
	}
	for _, c := range cases {
		err := runComplete(c.exit, readTestdata(t, c.file))
		if (err == nil) != c.complete {
			t.Errorf("%s: err = %v, want complete %v", c.name, err, c.complete)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %q, want it to mention %q", c.name, err, c.wantErr)
		}
	}
}

func TestRunCompleteRejectsIncompleteJSON(t *testing.T) {
	ok := readTestdata(t, "testssl_ok.json")
	interrupted := strings.Replace(string(ok), `"scanTime"  : 32`, `"scanTime"  : "Scan interrupted"`, 1)
	noScanTime := strings.Replace(string(ok), `"scanTime"  : 32`, `"x" : 1`, 1)
	problem := strings.Replace(string(ok), `"id"           : "LUCKY13"`, `"id"           : "scanProblem"`, 1)

	for name, data := range map[string]string{
		"empty":                   "",
		"cut off (killed run)":    string(ok[:len(ok)/2]),
		"scanTime interrupted":    interrupted,
		"no scanTime":             noScanTime,
		"scanProblem in findings": problem,
		"scanProblem at top":      `{"scanResult":[{"id":"scanProblem","severity":"FATAL","finding":"x"}],"scanTime":3}`,
	} {
		if err := runComplete(0, []byte(data)); err == nil {
			t.Errorf("%s: complete, want an error", name)
		}
	}
	if !strings.Contains(problem, "scanProblem") || !strings.Contains(interrupted, "Scan interrupted") {
		t.Fatal("testdata changed: the replacements did not apply")
	}
}

func TestRunCompleteIgnoresClientProblem(t *testing.T) {
	// Every run has a top-level clientProblem1 WARN (no GOST engine): it is not a scan problem.
	data := `{"clientProblem1":[{"id":"engine_problem","severity":"WARN","finding":"No engine"}],"scanResult":[{"vulnerabilities":[]}],"scanTime":5}`
	if err := runComplete(0, []byte(data)); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}
