package nuclei_scanner

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

// A run the target cut short (dropped as unresponsive) is expected and logged at Warn; a
// failure of the scanner itself (nuclei exits non-zero, [FTL], no completed scan) stays Error.
func TestRunFailureIsTargetSide(t *testing.T) {
	completed := "[INF] Scan completed in 1m. No results found.\n"
	cases := map[string]struct {
		stderr     string
		code       int
		targetSide bool
	}{
		"target dropped":        {cdnTimeoutLog(t, "example.com"), 0, true},
		"no templates (exit 1)": {"[FTL] Could not run nuclei: no templates provided for scan\n", 1, false},
		"fatal log, exit 0":     {"[FTL] something broke\n" + completed, 0, false},
		"no completed scan":     {"[INF] Loading templates\n", 0, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fakeNuclei(t, "", tc.stderr, tc.code)
			s := &Service{logger: zap.NewNop()}
			_, err := s.runNucleiScan(context.Background(), "example.com", "low")
			if err == nil {
				t.Fatal("err = nil, want a failed run")
			}
			if got := isTargetSide(err); got != tc.targetSide {
				t.Fatalf("isTargetSide(%v) = %v, want %v", err, got, tc.targetSide)
			}
		})
	}
}

// A missing nuclei binary is a scanner fault.
func TestMissingBinaryIsNotTargetSide(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	s := &Service{logger: zap.NewNop()}
	_, err := s.runNucleiScan(context.Background(), "example.com", "low")
	if err == nil || isTargetSide(err) {
		t.Fatalf("err = %v, want a scanner-side failure", err)
	}
}
