package scan_coordinator

import "github.com/VulWall/VulWall/scanner/src/internal/shared"

// StreamGroup identifies one Redis stream consumer group that participates in the
// finding-producing path of a scan.
type StreamGroup struct {
	Stream string
	Group  string
}

// scanPipelineGroups is the authoritative set of (stream, consumer-group) pairs that must
// be fully drained before a scan is complete. Mirrors the "Scan Monitor Coverage" table in
// docs/SERVICE_REGISTRY.md; a new stage must be added here (pipeline_test.go fails CI if this
// drifts).
//
// The order matters: upstream stages come before the stages they feed. pipelineQuiescent
// reads the groups in this order, and every stage publishes its results before it ACKs its
// input, so a drained upstream group read first cannot hide results it published after a
// downstream stream was already read.
//
// Enrichment and KB streams are excluded on purpose: they are terminal (no new findings or
// triggers), and KB generation is a slow cross-org Anthropic queue whose backlog would
// otherwise stall unrelated scans' completion.
func scanPipelineGroups() []StreamGroup {
	return []StreamGroup{
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
}

// ownedGroups is every (stream, consumer-group) pair the nightwatch binary consumes: the
// scan-pipeline groups plus the terminal enrichment, KB and audit groups. At startup
// ReleaseOrphanedPending deletes the previous process's consumers from all of them.
// Mirrors the Component Inventory in docs/SERVICE_REGISTRY.md (pipeline_test.go checks it).
func ownedGroups() []StreamGroup {
	return append(scanPipelineGroups(),
		StreamGroup{shared.StreamDiscoveryEnrichmentQueue, "discovery_enrichment_service"},
		StreamGroup{shared.StreamDiscoveryEnrichmentResults, "enrichment_ingestion_service"},
		StreamGroup{shared.StreamKBGenerationQueue, "knowledge_base_engine_service"},
		StreamGroup{shared.StreamKBGenerationResults, "kb_ingestion_service"},
		StreamGroup{shared.StreamSystemAuditLogs, "audit_ingestion_service"},
	)
}
