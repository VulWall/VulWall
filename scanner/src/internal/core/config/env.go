package config

// Environment variable names - single source of truth for all services.
// Using constants prevents typos and enables compile-time safety.
const (
	// ===========================================
	// Infrastructure
	// ===========================================

	// EnvRedisURI is the Redis connection string (e.g., redis://localhost:6379/0)
	EnvRedisURI = "REDIS_URI"
	// EnvMongoURI is the MongoDB connection string (e.g., mongodb://localhost:27017)
	EnvMongoURI = "MONGO_URI"
	// EnvMongoDB is the MongoDB database name (default: vulwall)
	EnvMongoDB = "MONGO_DB"

	// ===========================================
	// Service Configuration
	// ===========================================

	// EnvEnvironment is the deployment environment (development/production)
	EnvEnvironment = "ENVIRONMENT"
	// EnvVulWallVersion is the release the image was built from (scanner/Dockerfile build arg)
	EnvVulWallVersion = "VULWALL_VERSION"
	// EnvNucleiVersion and EnvTestSSLVersion are the pinned tool versions, set by scanner/Dockerfile
	EnvNucleiVersion  = "NUCLEI_VERSION"
	EnvTestSSLVersion = "TESTSSL_VERSION"

	// ===========================================
	// API Keys
	// ===========================================

	// EnvAnthropicAPIKey is the Anthropic API key for knowledge base generation
	EnvAnthropicAPIKey = "ANTHROPIC_API_KEY"
	// EnvAnthropicModel is the Anthropic model to use (default: claude-sonnet-4-6)
	EnvAnthropicModel = "ANTHROPIC_MODEL"

	// ===========================================
	// OpenTelemetry / Tracing
	// ===========================================

	// EnvOTELEnabled enables distributed tracing (true/false, default false)
	EnvOTELEnabled = "OTEL_ENABLED"
	// EnvOTELTraceSampler is the sampling strategy (e.g., parentbased_always_on)
	EnvOTELTraceSampler = "OTEL_TRACES_SAMPLER"
	// EnvOTELTraceSamplerArg is the sampler argument (e.g., 0.1 for 10% sampling)
	EnvOTELTraceSamplerArg = "OTEL_TRACES_SAMPLER_ARG"
	// EnvOTELExporterEndpoint is the OTLP/HTTP base endpoint (e.g., http://jaeger:4318).
	// The exporter reads it, and OTEL_EXPORTER_OTLP_HEADERS, directly; it is
	// listed here for logging only.
	EnvOTELExporterEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"

	// OpenTelemetry Batch Span Processor Configuration

	// EnvOTELBSPScheduledDelay is the batch flush interval in milliseconds (default: 5000)
	EnvOTELBSPScheduledDelay = "OTEL_BSP_SCHEDULED_DELAY_MILLIS"
	// EnvOTELBSPMaxQueueSize is the maximum spans in queue before dropping (default: 2048)
	EnvOTELBSPMaxQueueSize = "OTEL_BSP_MAX_QUEUE_SIZE"
	// EnvOTELBSPMaxExportBatch is the number of spans per batch export (default: 512)
	EnvOTELBSPMaxExportBatch = "OTEL_BSP_MAX_EXPORT_BATCH_SIZE"
	// EnvOTELBSPExportTimeout is the export timeout in milliseconds (default: 30000)
	EnvOTELBSPExportTimeout = "OTEL_BSP_EXPORT_TIMEOUT_MILLIS"

	// ===========================================
	// Scanner Configuration
	// ===========================================

	// EnvNucleiTemplateUpdateCron is the cron schedule for Nuclei template updates (default: 0 2 * * *)
	EnvNucleiTemplateUpdateCron = "NUCLEI_TEMPLATE_UPDATE_CRON"
	// EnvNucleiTemplatesDir is where nuclei templates are installed (default: $HOME/nuclei-templates)
	EnvNucleiTemplatesDir = "NUCLEI_TEMPLATES_DIR"
	// EnvNucleiWorkers is the number of concurrent nuclei processes, shared by both trigger streams (default: 2)
	EnvNucleiWorkers = "NUCLEI_WORKERS"
	// EnvNucleiRateLimit is the nuclei request rate per process, requests per second (default: 30)
	EnvNucleiRateLimit = "NUCLEI_RATE_LIMIT"
	// EnvNucleiInteractsh turns on nuclei's out-of-band (OAST) checks through interactsh
	// servers: "on" or "true" (default: off, nuclei runs with -ni)
	EnvNucleiInteractsh = "NUCLEI_INTERACTSH"
	// EnvNucleiInteractshServer is the https URL of a self-hosted interactsh server (-iserver)
	EnvNucleiInteractshServer = "NUCLEI_INTERACTSH_SERVER"
	// EnvNucleiInteractshToken is the auth token of that server (-itoken). A secret: never logged
	EnvNucleiInteractshToken = "NUCLEI_INTERACTSH_TOKEN"
	// EnvNucleiIncludeTags is the comma-separated list of Nuclei template tags to include (empty = no filter)
	EnvNucleiIncludeTags = "NUCLEI_INCLUDE_TAGS"
	// EnvNucleiExcludeTags is the comma-separated list of Nuclei template tags to exclude (empty = no filter)
	EnvNucleiExcludeTags = "NUCLEI_EXCLUDE_TAGS"
	// EnvTestSSLConcurrency is the number of concurrent testssl.sh workers (default: 5)
	EnvTestSSLConcurrency = "TESTSSL_CONCURRENCY"
	// EnvIPEnrichmentDBPath is the path to the country MMDB file (e.g., DB-IP IP to Country Lite)
	EnvIPEnrichmentDBPath = "IP_ENRICHMENT_DB_PATH"
	// EnvIPASNDBPath is the path to the optional ASN MMDB file (e.g., DB-IP IP to ASN Lite); fills the ISP field
	EnvIPASNDBPath = "IP_ASN_DB_PATH"
	// EnvWAFRulesPath is the path to WAF detection rules JSON file
	EnvWAFRulesPath = "WAF_RULES_PATH"
	// EnvCloudDetectorEnabled enables/disables cloud provider detection (true/false)
	EnvCloudDetectorEnabled = "CLOUD_DETECTOR_ENABLED"
	// EnvCloudDataDir is the directory containing cloud provider data files
	EnvCloudDataDir = "CLOUD_DATA_DIR"
	// EnvScanIdleTimeout overrides the scan monitor's idle timeout (Go duration, default 15m)
	EnvScanIdleTimeout = "SCAN_IDLE_TIMEOUT"
	// EnvScanMinRuntime overrides the minimum scan age before a scan can complete
	// (Go duration, default 10m)
	EnvScanMinRuntime = "SCAN_MIN_RUNTIME"
	// EnvDNSResolveConcurrency is the number of concurrent subdomain DNS lookups in domain
	// discovery (default: 50)
	EnvDNSResolveConcurrency = "DNS_RESOLVE_CONCURRENCY"
	// EnvDNSRecheckResolvers lists the public resolvers (host or host:port, comma separated)
	// that domain discovery asks directly when the local resolver says a root domain does not
	// exist (default "1.1.1.1,8.8.8.8"). "off" disables the check, e.g. when outbound DNS is
	// blocked; such a root is then treated as a resolver failure.
	EnvDNSRecheckResolvers = "DNS_RECHECK_RESOLVERS"
	// EnvAllowPrivateTargets disables the private/reserved IP guard for scan
	// targets (true/false, default false). Only enable it for self-hosted
	// installs that intentionally scan internal networks.
	EnvAllowPrivateTargets = "ALLOW_PRIVATE_TARGETS"
)
