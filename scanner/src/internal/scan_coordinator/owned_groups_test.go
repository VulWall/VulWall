package scan_coordinator

import (
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/discovery_enrichment"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/email_security_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/http_header_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/js_dependency_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/nuclei_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/testssl_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/domain_discovery"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/port_discovery"
	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/domain_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/enrichment_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/findings_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/kb_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/port_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
)

// TestOwnedGroups checks that startup cleanup covers every group a component consumes, under
// the name the component uses. pipeline.go spells the names out; this ties them to the
// components' own constants.
func TestOwnedGroups(t *testing.T) {
	want := map[StreamGroup]bool{
		{shared.StreamDomainDiscoveryQueue, domain_discovery.GroupDomainDiscovery}:               true,
		{shared.StreamIPDiscoveryQueue, port_discovery.GroupPortDiscovery}:                       true,
		{shared.StreamDomainScanTriggers, nuclei_scanner.GroupNucleiScanner}:                     true,
		{shared.StreamPortScanTriggers, nuclei_scanner.GroupNucleiScanner}:                       true,
		{shared.StreamDomainScanTriggers, testssl_scanner.GroupTestSSLScanner}:                   true,
		{shared.StreamDomainScanTriggers, js_dependency_scanner.GroupJSDependencyScanner}:        true,
		{shared.StreamDomainScanTriggers, http_header_scanner.GroupHTTPHeaderScanner}:            true,
		{shared.StreamDomainScanTriggers, email_security_scanner.GroupEmailSecurityScanner}:      true,
		{shared.StreamDiscoveryEnrichmentQueue, discovery_enrichment.GroupDiscoveryEnrichment}:   true,
		{shared.StreamKBGenerationQueue, knowledge_base.GroupKBEngine}:                           true,
		{shared.StreamDomainDiscoveryResults, domain_ingestion.GroupDomainIngestion}:             true,
		{shared.StreamIPDiscoveryResults, port_ingestion.GroupPortIngestion}:                     true,
		{shared.StreamSecurityFindings, findings_ingestion.GroupFindingsIngestion}:               true,
		{shared.StreamDiscoveryEnrichmentResults, enrichment_ingestion.GroupEnrichmentIngestion}: true,
		{shared.StreamKBGenerationResults, kb_ingestion.GroupKBIngestion}:                        true,
	}

	got := ownedGroups()
	seen := map[StreamGroup]bool{}
	for _, sg := range got {
		if seen[sg] {
			t.Errorf("duplicate pair %+v", sg)
		}
		seen[sg] = true
		if !want[sg] {
			t.Errorf("unexpected pair %+v (wrong name, or a new component missing here)", sg)
		}
	}
	for sg := range want {
		if !seen[sg] {
			t.Errorf("missing pair %+v", sg)
		}
	}
	for _, sg := range scanPipelineGroups() {
		if !seen[sg] {
			t.Errorf("pipeline pair %+v is not in ownedGroups", sg)
		}
	}
}
