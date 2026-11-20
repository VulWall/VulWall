package patterns

import (
	"net/http"
	"testing"

	"go.uber.org/zap"
)

// The PT Application Firewall rule used to include a generic
// "<h1>Forbidden" check. With the detector's 2-of-N matching, any plain 403
// page matched it, so the rule was dropped. It now uses PT-specific checks
// only; a generic 403 page must not be attributed to PT.
func TestPTApplicationFirewallSignature(t *testing.T) {
	d, err := NewDetector(zap.NewNop(), testRulesPath)
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	var pt WAFSignature
	for _, sig := range d.signatures {
		if sig.Name == "PT Application Firewall" {
			pt = sig
		}
	}
	if pt.Name == "" {
		t.Fatal("PT Application Firewall signature not loaded")
	}

	generic403 := &HTTPResponse{
		StatusCode: 403,
		Headers:    http.Header{},
		Body:       "<html><body><h1>Forbidden</h1><p>You don't have permission.</p></body></html>",
	}
	if d.matchSignature(generic403, pt) {
		t.Error("generic 403 page must not match PT Application Firewall")
	}

	ptBlock := &HTTPResponse{
		StatusCode: 403,
		Headers:    http.Header{},
		Body:       "<h1>Forbidden</h1><pre>Request ID: 2024-05-17-12-30-45-ABCDEF</pre>",
	}
	if !d.matchSignature(ptBlock, pt) {
		t.Error("PT block page with Request ID must match PT Application Firewall")
	}
}
