package nuclei_scanner

import (
	"encoding/json"
	"slices"
	"testing"

	"go.uber.org/zap"
)

func TestConvertKeepsTemplateText(t *testing.T) {
	line := `{"template-id":"CVE-2021-41773","info":{"name":"Apache path traversal","severity":"critical",` +
		`"description":"Path traversal in Apache 2.4.49.","remediation":"Upgrade to 2.4.51.",` +
		`"reference":["https://httpd.apache.org/security/vulnerabilities_24.html"]}}`
	var out NucleiOutput
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatal(err)
	}

	f := (&Service{logger: zap.NewNop()}).convertToSecurityFinding(out, ScanTarget{OrgID: "o"})

	if f.Description != "Path traversal in Apache 2.4.49." || f.Remediation != "Upgrade to 2.4.51." {
		t.Fatalf("description/remediation = %q / %q", f.Description, f.Remediation)
	}
	if !slices.Equal(f.References, []string{"https://httpd.apache.org/security/vulnerabilities_24.html"}) {
		t.Fatalf("references = %v", f.References)
	}
}
