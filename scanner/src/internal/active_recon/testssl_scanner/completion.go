package testssl_scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// testssl.sh 3.2.5 exit codes: 0 when every check ran; 1 to 239 the number of checks that
// could not run (each also a WARN entry, for example "OpenSSL handshake didn't succeed"); 240
// and up a fatal ERR_* code (246 ERR_CONNECT, 247 ERR_DNSLOOKUP, ...), after which the JSON
// holds a "scanProblem" FATAL entry and "scanTime": "Scan interrupted". A run that reached the
// end writes "scanTime" as a number. A found vulnerability does not change the exit code.
const testsslFatalExit = 240

// runComplete returns nil only for a testssl.sh run that provably checked everything: exit
// code 0 and a JSON file that ends with a numeric scanTime and has no scanProblem or FATAL
// entry. Anything else is an error, so the run is coverage "error" and resolves nothing.
func runComplete(exitCode int, jsonData []byte) error {
	switch {
	case exitCode >= testsslFatalExit:
		return fmt.Errorf("testssl.sh stopped with fatal exit code %d%s", exitCode, problemSuffix(jsonData))
	case exitCode > 0:
		return fmt.Errorf("testssl.sh could not run %d check(s) (exit code %d)", exitCode, exitCode)
	}
	if len(strings.TrimSpace(string(jsonData))) == 0 {
		return errors.New("testssl.sh wrote no JSON output")
	}

	var out struct {
		ScanResult []json.RawMessage `json:"scanResult"`
		ScanTime   json.RawMessage   `json:"scanTime"`
	}
	if err := json.Unmarshal(jsonData, &out); err != nil {
		return fmt.Errorf("testssl.sh JSON output is incomplete or invalid: %w", err)
	}
	var seconds float64
	if len(out.ScanTime) == 0 || json.Unmarshal(out.ScanTime, &seconds) != nil {
		return fmt.Errorf("testssl.sh did not finish the scan (scanTime %s)%s", strings.TrimSpace(string(out.ScanTime)), problemSuffix(jsonData))
	}
	if p := scanProblem(out.ScanResult); p != "" {
		return fmt.Errorf("testssl.sh reported a scan problem: %s", p)
	}
	return nil
}

// scanProblem returns the finding of the first scanProblem or FATAL entry, either directly in
// scanResult or in one of the finding lists of a scanResult entry, or "".
func scanProblem(results []json.RawMessage) string {
	isProblem := func(f TestSSLFinding) bool {
		return f.ID == "scanProblem" || strings.EqualFold(f.Severity, "FATAL")
	}
	for _, raw := range results {
		var f TestSSLFinding
		if json.Unmarshal(raw, &f) == nil && isProblem(f) {
			return f.Finding
		}
		var host map[string]json.RawMessage
		if json.Unmarshal(raw, &host) != nil {
			continue
		}
		for _, v := range host {
			var list []TestSSLFinding
			if json.Unmarshal(v, &list) != nil {
				continue
			}
			for _, f := range list {
				if isProblem(f) {
					return f.Finding
				}
			}
		}
	}
	return ""
}

// problemSuffix is ": <finding>" of the scan problem in jsonData, for error messages.
func problemSuffix(jsonData []byte) string {
	var out struct {
		ScanResult []json.RawMessage `json:"scanResult"`
	}
	if json.Unmarshal(jsonData, &out) != nil {
		return ""
	}
	if p := scanProblem(out.ScanResult); p != "" {
		return ": " + p
	}
	return ""
}
