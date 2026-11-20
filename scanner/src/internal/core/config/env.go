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
	// EnvMongoDB is the MongoDB database name (e.g., VulWall-Dev)
	EnvMongoDB = "MONGO_DB"

	// ===========================================
	// Service Configuration
	// ===========================================

	// EnvServiceName is the service identifier for logging and telemetry
	EnvServiceName = "SERVICE_NAME"
	// EnvEnvironment is the deployment environment (development/production)
	EnvEnvironment = "ENVIRONMENT"

	// ===========================================
	// API Keys
	// ===========================================

	// EnvAnthropicAPIKey is the Anthropic API key for knowledge base generation
	EnvAnthropicAPIKey = "ANTHROPIC_API_KEY"
	// EnvAnthropicModel is the Anthropic model to use (default: claude-sonnet-4-5-20250514)
	EnvAnthropicModel = "ANTHROPIC_MODEL"

	// ===========================================
	// OpenTelemetry / Tracing
	// ===========================================

	// EnvOTELEnabled enables/disables distributed tracing (true/false)
	EnvOTELEnabled = "OTEL_ENABLED"
	// EnvOTELTraceSampler is the sampling strategy (e.g., parentbased_always_on)
	EnvOTELTraceSampler = "OTEL_TRACES_SAMPLER"
	// EnvOTELTraceSamplerArg is the sampler argument (e.g., 0.1 for 10% sampling)
	EnvOTELTraceSamplerArg = "OTEL_TRACES_SAMPLER_ARG"
	// EnvOTELExporterEndpoint is the OTLP endpoint (e.g., api.honeycomb.io)
	EnvOTELExporterEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"
	// EnvHoneycombAPIKey is the Honeycomb API key for observability
	EnvHoneycombAPIKey = "HONEYCOMB_API_KEY"

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
	// EnvNucleiIncludeTags is the comma-separated list of Nuclei template tags to include (empty = no filter)
	EnvNucleiIncludeTags = "NUCLEI_INCLUDE_TAGS"
	// EnvNucleiExcludeTags is the comma-separated list of Nuclei template tags to exclude (empty = no filter)
	EnvNucleiExcludeTags = "NUCLEI_EXCLUDE_TAGS"
	// EnvTestSSLConcurrency is the number of concurrent testssl.sh workers (default: 5)
	EnvTestSSLConcurrency = "TESTSSL_CONCURRENCY"
	// EnvIPEnrichmentDBPath is the path to MaxMind GeoIP MMDB file
	EnvIPEnrichmentDBPath = "IP_ENRICHMENT_DB_PATH"
	// EnvWAFRulesPath is the path to WAF detection rules JSON file
	EnvWAFRulesPath = "WAF_RULES_PATH"
	// EnvCloudDetectorEnabled enables/disables cloud provider detection (true/false)
	EnvCloudDetectorEnabled = "CLOUD_DETECTOR_ENABLED"
	// EnvCloudDataDir is the directory containing cloud provider data files
	EnvCloudDataDir = "CLOUD_DATA_DIR"
	// EnvAllowPrivateTargets disables the private/reserved IP guard for scan
	// targets (true/false, default false). Only enable it for self-hosted
	// installs that intentionally scan internal networks.
	EnvAllowPrivateTargets = "ALLOW_PRIVATE_TARGETS"
)
