package knowledge_base

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/ai"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:embed prompts/*.txt prompts/*.json
var promptsFS embed.FS

const (
	// kbToolName names the structured output. The prompts refer to it.
	kbToolName        = "generate_kb_entry"
	kbToolDescription = "Generate a structured knowledge base entry for a security vulnerability finding, " +
		"covering business impact, technical details, and metadata."
	// kbMaxOutputTokens covers thinking, searches and the entry.
	kbMaxOutputTokens = 16000
)

// ProviderSource returns the AI provider for the current configuration.
// provider.Resolver implements it.
type ProviderSource interface {
	Provider(ctx context.Context) (ai.Provider, error)
}

// Service generates knowledge base entries with the configured AI provider.
type Service struct {
	redis          *redis.Client
	providers      ProviderSource
	logger         *zap.Logger
	tracer         trace.Tracer
	systemPrompt   string // core rules; composeSystemPrompt adds the search-dependent part
	webSearchPart  string
	noSearchPart   string
	responseSchema json.RawMessage // cached at startup; embedded FS never changes at runtime
}

// NewService creates a new knowledge base engine service
func NewService(redisClient *redis.Client, providers ProviderSource, logger *zap.Logger) (*Service, error) {
	s := &Service{
		redis:     redisClient,
		providers: providers,
		logger:    logger,
		tracer:    otel.Tracer("knowledge-base-engine"),
	}

	// Load system prompt
	if err := s.loadSystemPrompt(); err != nil {
		return nil, fmt.Errorf("failed to load system prompt: %w", err)
	}

	// Cache the response schema used as the tool's input_schema for structured output.
	// Loading it once at startup is consistent with how the system prompt is handled,
	// and the embedded FS never changes between calls.
	if err := s.loadResponseSchema(); err != nil {
		return nil, fmt.Errorf("failed to load response schema: %w", err)
	}

	return s, nil
}

// loadSystemPrompt loads the prompt parts from the embedded filesystem.
func (s *Service) loadSystemPrompt() error {
	for name, dst := range map[string]*string{
		"system_prompt.txt": &s.systemPrompt,
		"web_search.txt":    &s.webSearchPart,
		"no_web_search.txt": &s.noSearchPart,
	} {
		content, err := promptsFS.ReadFile("prompts/" + name)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", name, err)
		}
		*dst = strings.TrimSpace(string(content))
	}
	return nil
}

// composeSystemPrompt returns the system prompt for a provider with or
// without web search. Without it the prompt never mentions searching, and
// references must be null.
func (s *Service) composeSystemPrompt(webSearch bool) string {
	part := s.noSearchPart
	if webSearch {
		part = s.webSearchPart
	}
	return s.systemPrompt + "\n\n" + part + "\n"
}

// loadResponseSchema loads and caches the JSON Schema from embedded filesystem.
// This schema is passed as the tool's input_schema to enforce structured output.
func (s *Service) loadResponseSchema() error {
	content, err := promptsFS.ReadFile("prompts/response_schema.json")
	if err != nil {
		return fmt.Errorf("failed to read response_schema.json: %w", err)
	}

	// Validate well-formed JSON at startup — catches build-time corruption early
	// rather than producing opaque 400 errors from the provider at runtime.
	if !json.Valid(content) {
		return fmt.Errorf("response_schema.json is not valid JSON")
	}

	s.responseSchema = json.RawMessage(content)

	s.logger.Info("Loaded response schema",
		zap.Int("length", len(content)),
	)

	return nil
}

// ProcessJob processes a KB generation job and produces a knowledge base entry
func (s *Service) ProcessJob(ctx context.Context, job shared.KBGenerationJob) error {
	ctx, span := s.tracer.Start(ctx, "process_kb_generation_job",
		trace.WithAttributes(
			attribute.String("trace.id", job.TraceID),
			attribute.String("finding.type", job.FindingType),
			attribute.String("severity", job.Severity),
		),
	)
	defer span.End()

	s.logger.Info("Processing KB generation job",
		zap.String("finding_type", job.FindingType),
		zap.String("severity", job.Severity),
		zap.String("title", job.Title),
	)

	fail := func(err error) error {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	provider, err := s.providers.Provider(ctx)
	if err != nil {
		return fail(fmt.Errorf("AI provider: %w", err))
	}
	webSearch := provider.Capabilities().WebSearch

	result, err := provider.Generate(ctx, ai.Request{
		System:          s.composeSystemPrompt(webSearch),
		User:            s.buildJobContext(job),
		MaxOutputTokens: kbMaxOutputTokens,
		Schema:          &ai.Schema{Name: kbToolName, Description: kbToolDescription, JSON: s.responseSchema},
		WebSearch:       webSearch,
	})
	if err != nil {
		return fail(fmt.Errorf("failed to generate KB entry: %w", err))
	}
	span.SetAttributes(attribute.String("ai.outcome", string(result.Outcome)), attribute.String("ai.model", result.Model))
	s.logger.Info("KB generation finished",
		zap.String("finding_type", job.FindingType),
		zap.String("model", result.Model),
		zap.String("outcome", string(result.Outcome)),
		zap.Int("input_tokens", result.Usage.InputTokens),
		zap.Int("output_tokens", result.Usage.OutputTokens),
		zap.Int("web_searches", result.WebSearches),
	)

	// Without a usable entry, no KB document is written and findings keep the
	// scanners' own text.
	switch result.Outcome {
	case ai.OutcomeOK:
	case ai.OutcomeRefused:
		return fail(fmt.Errorf("KB generation for %s refused (category %q)", job.FindingType, result.RefusalCategory))
	default:
		return fail(fmt.Errorf("KB generation for %s ended without an entry (outcome %s)", job.FindingType, result.Outcome))
	}
	if err := validateEntry(result.JSON); err != nil {
		return fail(fmt.Errorf("invalid KB entry for %s: %w", job.FindingType, err))
	}
	entry, err := normalizeEntry(result.JSON, webSearch)
	if err != nil {
		return fail(fmt.Errorf("invalid KB entry for %s: %w", job.FindingType, err))
	}

	// Publish result to stream
	if err := s.publishResult(ctx, job, entry, result.Model); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// buildJobContext creates a context string from the KB generation job
func (s *Service) buildJobContext(job shared.KBGenerationJob) string {
	var sb strings.Builder

	sb.WriteString("## Security Finding\n\n")
	sb.WriteString(fmt.Sprintf("**Finding Type:** %s\n", job.FindingType))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", job.Severity))
	sb.WriteString(fmt.Sprintf("**Scanner:** %s\n", job.Source))

	// Title and Description come from scanner output and may contain
	// attacker-influenced content. Wrap in XML tags so the system prompt
	// can instruct Claude to treat them as untrusted data, not instructions.
	if job.Title != "" {
		sb.WriteString(fmt.Sprintf("\n**Title:**\n<scanner_title>%s</scanner_title>\n", job.Title))
	}

	if job.Description != "" {
		sb.WriteString(fmt.Sprintf("\n**Description:**\n<scanner_description>%s</scanner_description>\n", job.Description))
	}

	// Include allowlisted metadata fields (already filtered by safeMetadataForKB)
	if len(job.Metadata) > 0 {
		sb.WriteString("\n**Additional Details:**\n<scanner_metadata>\n")
		for key, value := range job.Metadata {
			sb.WriteString(fmt.Sprintf("- %s: %s\n", key, formatMetadataValue(value)))
		}
		sb.WriteString("</scanner_metadata>\n")
	}

	return sb.String()
}

// formatMetadataValue converts metadata values to readable strings
func formatMetadataValue(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		if len(v) > 2000 {
			return v[:2000] + "... (truncated)"
		}
		return v
	case []interface{}:
		var parts []string
		for _, item := range v {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		result := strings.Join(parts, ", ")
		if len(result) > 1000 {
			return result[:1000] + "... (truncated)"
		}
		return result
	case map[string]interface{}:
		var parts []string
		for k, val := range v {
			parts = append(parts, fmt.Sprintf("%s=%v", k, val))
		}
		result := strings.Join(parts, ", ")
		if len(result) > 1000 {
			return result[:1000] + "... (truncated)"
		}
		return result
	default:
		return fmt.Sprintf("%v", v)
	}
}

// publishResult publishes the KB generation result to the stream
func (s *Service) publishResult(ctx context.Context, job shared.KBGenerationJob, entry map[string]any, model string) error {
	result := shared.KBGenerationResult{
		FindingType: job.FindingType,
		Entry:       entry,
		Model:       model,
		TraceID:     job.TraceID,
		Timestamp:   time.Now(),
	}

	// Inject trace context for distributed tracing
	result.TraceContext = telemetry.InjectTraceContext(ctx)

	// Publish WITHOUT MAXLEN — safe cleanup job handles trimming
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamKBGenerationResults, result, 0); err != nil {
		return fmt.Errorf("failed to publish KB result: %w", err)
	}

	s.logger.Info("Published KB generation result",
		zap.String("finding_type", job.FindingType),
		zap.String("model", model),
	)

	return nil
}
