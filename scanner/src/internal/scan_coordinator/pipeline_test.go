package scan_coordinator

import (
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// TestScanPipelineGroups locks the authoritative completion-coverage set. It is the guard
// against the documented "added a scanner but forgot the scan monitor" hazard (CLAUDE.md,
// "Adding a New Scanner", step 3): if a scanner's (stream, group) pair is added or removed
// without a matching update here and in docs/SERVICE_REGISTRY.md, this test fails.
//
// Enrichment/KB streams must NEVER appear here — they are terminal branches that produce no
// findings or triggers, and gating scan completion on the cross-org KB queue would let one
// org's backlog stall every other org's scans.
func TestScanPipelineGroups(t *testing.T) {
	t.Parallel()

	// Upstream stages first: pipelineQuiescent depends on this order.
	want := []StreamGroup{
		{shared.StreamDomainDiscoveryQueue, "domain_discovery_service"},
		{shared.StreamDomainDiscoveryResults, "domain_ingestion_service"},
		{shared.StreamIPDiscoveryQueue, "port_discovery_service"},
		{shared.StreamIPDiscoveryResults, "port_ingestion_service"},
		{shared.StreamDomainScanTriggers, "nuclei_scanner_service"},
		{shared.StreamDomainScanTriggers, "testssl_scanner_service"},
		{shared.StreamDomainScanTriggers, "js_dependency_scanner_service"},
		{shared.StreamDomainScanTriggers, "http_header_scanner_service"},
		{shared.StreamDomainScanTriggers, "email_security_scanner_service"},
		{shared.StreamPortScanTriggers, "nuclei_scanner_service"},
		{shared.StreamSecurityFindings, "findings_ingestion_service"},
	}

	got := scanPipelineGroups()

	if len(got) != len(want) {
		t.Fatalf("scanPipelineGroups() returned %d pairs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pair %d = %+v, want %+v — update this test AND docs/SERVICE_REGISTRY.md", i, got[i], want[i])
		}
	}

	// Enrichment and KB streams are terminal and must be excluded.
	for _, sg := range got {
		switch sg.Stream {
		case shared.StreamDiscoveryEnrichmentResults,
			shared.StreamDiscoveryEnrichmentQueue,
			shared.StreamKBGenerationResults,
			shared.StreamKBGenerationQueue:
			t.Errorf("enrichment/KB stream %q must not be in the completion-coverage set", sg.Stream)
		}
	}
}
