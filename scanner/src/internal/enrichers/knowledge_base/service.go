package knowledge_base

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base/anthropic"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:embed prompts/*.txt prompts/*.json
var promptsFS embed.FS

// Service handles knowledge base entry generation using Anthropic Claude
type Service struct {
	redis           *redis.Client
	anthropicClient *anthropic.Client
	logger          *zap.Logger
	tracer          trace.Tracer
	systemPrompt    string
	responseSchema  json.RawMessage // cached at startup; embedded FS never changes at runtime
}

// NewService creates a new knowledge base engine service
func NewService(redisClient *redis.Client, anthropicClient *anthropic.Client, logger *zap.Logger) (*Service, error) {
	s := &Service{
		redis:          redisClient,
		anthropicClient: anthropicClient,
		logger:         logger,
		tracer:         otel.Tracer("knowledge-base-engine"),
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

// loadSystemPrompt loads the system prompt from embedded filesystem
func (s *Service) loadSystemPrompt() error {
	content, err := promptsFS.ReadFile("prompts/system_prompt.txt")
	if err != nil {
		return fmt.Errorf("failed to read system_prompt.txt: %w", err)
	}

	s.systemPrompt = string(content)

	s.logger.Info("Loaded system prompt",
		zap.Int("length", len(content)),
	)

	return nil
}

// loadResponseSchema loads and caches the JSON Schema from embedded filesystem.
// This schema is passed as the tool's input_schema to enforce structured output.
func (s *Service) loadResponseSchema() error {
	content, err := promptsFS.ReadFile("prompts/response_schema.json")
	if err != nil {
		return fmt.Errorf("failed to read response_schema.json: %w", err)
	}

	// Validate well-formed JSON at startup — catches build-time corruption early
	// rather than producing opaque 400 errors from Anthropic at runtime.
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

	// Build finding context for Claude
	findingContext := s.buildJobContext(job)

	// Generate KB entry via Anthropic structured output.
	// The schema (cached at startup) is passed as the tool's input_schema, so the
	// Anthropic API enforces that Claude's response matches it exactly — no prompt-level
	// schema injection is needed and markdown-wrapped or malformed JSON is impossible.
	responseText, err := s.anthropicClient.GenerateKBEntry(ctx, s.systemPrompt, findingContext, s.responseSchema)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to generate KB entry: %w", err)
	}

	s.logger.Info("KB entry generated",
		zap.String("finding_type", job.FindingType),
		zap.Int("response_length", len(responseText)),
	)

	// Publish result to stream
	if err := s.publishResult(ctx, job, responseText); err != nil {
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
func (s *Service) publishResult(ctx context.Context, job shared.KBGenerationJob, responseJSON string) error {
	// Parse JSON response into map for structured storage.
	// With structured output (tool_use), the response is guaranteed valid JSON by the
	// Anthropic API — this unmarshal should never fail in normal operation.
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(responseJSON), &entry); err != nil {
		s.logger.Error("Failed to parse KB response as JSON, skipping publish to prevent corrupt entry",
			zap.Error(err),
			zap.String("finding_type", job.FindingType),
			zap.Int("response_length", len(responseJSON)),
		)
		return fmt.Errorf("unparseable KB response for %s: %w", job.FindingType, err)
	}

	result := shared.KBGenerationResult{
		FindingType: job.FindingType,
		Entry:       entry,
		Model:       s.anthropicClient.GetModel(),
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
		zap.String("model", s.anthropicClient.GetModel()),
	)

	return nil
}
