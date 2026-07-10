package scan_coordinator

import "github.com/vulwall/scanners/internal/shared"

// StreamGroup identifies one Redis stream consumer group that participates in the
// finding-producing path of a scan.
type StreamGroup struct {
	Stream string
	Group  string
}

// scanPipelineGroups is the authoritative set of (stream, consumer-group) pairs that must
// be fully drained before a scan is complete. Mirrors the "Scan Monitor Coverage" table in
// docs/SERVICE_REGISTRY.md; a new active-recon scanner must be added here (pipeline_test.go
// fails CI if this drifts).
//
// Enrichment and KB streams are excluded on purpose: they are terminal (no new findings or
// triggers), and KB generation is a slow cross-org Anthropic queue whose backlog would
// otherwise stall unrelated scans' completion.
func scanPipelineGroups() []StreamGroup {
	return []StreamGroup{
		{shared.StreamDomainScanTriggers, "nuclei_scanner_service"},
		{shared.StreamDomainScanTriggers, "testssl_scanner_service"},
		{shared.StreamDomainScanTriggers, "js_dependency_scanner_service"},
		{shared.StreamDomainScanTriggers, "http_header_scanner_service"},
		{shared.StreamDomainScanTriggers, "email_security_scanner_service"},
		{shared.StreamPortScanTriggers, "nuclei_scanner_service"},
		{shared.StreamDomainDiscoveryResults, "domain_ingestion_service"},
		{shared.StreamIPDiscoveryResults, "port_ingestion_service"},
		{shared.StreamSecurityFindings, "findings_ingestion_service"},
	}
}
