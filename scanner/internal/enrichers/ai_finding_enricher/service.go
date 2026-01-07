package ai_finding_enricher

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vulwall/scanners/internal/core/redisx"
	"github.com/vulwall/scanners/internal/core/telemetry"
	"github.com/vulwall/scanners/internal/enrichers/ai_finding_enricher/groq"
	"github.com/vulwall/scanners/internal/shared"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

//go:embed prompts/*.txt prompts/*.json
var promptsFS embed.FS

// Service handles AI-powered finding enrichment
type Service struct {
	redis           *redis.Client
	groqClient      *groq.Client
	logger          *zap.Logger
	tracer          trace.Tracer
	prompts         map[string]string
	responseSchemas map[string]*groq.JSONSchema
}

// NewService creates a new AI finding enricher service
func NewService(redisClient *redis.Client, groqClient *groq.Client, logger *zap.Logger) (*Service, error) {
	s := &Service{
		redis:           redisClient,
		groqClient:      groqClient,
		logger:          logger,
		tracer:          otel.Tracer("ai-finding-enricher"),
		prompts:         make(map[string]string),
		responseSchemas: make(map[string]*groq.JSONSchema),
	}

	// Load embedded prompts and schemas
	if err := s.loadPrompts(); err != nil {
		return nil, fmt.Errorf("failed to load prompts: %w", err)
	}

	if err := s.loadResponseSchemas(); err != nil {
		return nil, fmt.Errorf("failed to load response schemas: %w", err)
	}

	return s, nil
}

// loadPrompts loads all prompt files from the embedded filesystem
func (s *Service) loadPrompts() error {
	entries, err := promptsFS.ReadDir("prompts")
	if err != nil {
		return fmt.Errorf("failed to read prompts directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}

		content, err := promptsFS.ReadFile("prompts/" + entry.Name())
		if err != nil {
			return fmt.Errorf("failed to read prompt %s: %w", entry.Name(), err)
		}

		// Remove .txt extension for the key
		name := strings.TrimSuffix(entry.Name(), ".txt")
		s.prompts[name] = string(content)

		s.logger.Info("Loaded prompt",
			zap.String("name", name),
			zap.Int("length", len(content)),
		)
	}

	if len(s.prompts) == 0 {
		return fmt.Errorf("no prompts found")
	}

	return nil
}

// loadResponseSchemas loads all JSON schema files from the embedded filesystem
func (s *Service) loadResponseSchemas() error {
	entries, err := promptsFS.ReadDir("prompts")
	if err != nil {
		return fmt.Errorf("failed to read prompts directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		content, err := promptsFS.ReadFile("prompts/" + entry.Name())
		if err != nil {
			return fmt.Errorf("failed to read schema %s: %w", entry.Name(), err)
		}

		// Parse JSON schema
		var schemaFile struct {
			Name   string                 `json:"name"`
			Schema map[string]interface{} `json:"schema"`
		}
		if err := json.Unmarshal(content, &schemaFile); err != nil {
			return fmt.Errorf("failed to parse schema %s: %w", entry.Name(), err)
		}

		// Remove .json extension and _schema suffix for the key
		name := strings.TrimSuffix(entry.Name(), ".json")
		name = strings.TrimSuffix(name, "_schema")

		s.responseSchemas[name] = &groq.JSONSchema{
			Name:   schemaFile.Name,
			Schema: schemaFile.Schema,
		}

		s.logger.Info("Loaded response schema",
			zap.String("name", name),
			zap.String("schema_name", schemaFile.Name),
		)
	}

	return nil
}

// getResponseSchema returns the response schema for the given name
func (s *Service) getResponseSchema(name string) *groq.JSONSchema {
	return s.responseSchemas[name]
}

// ProcessJob processes an AI enrichment job and generates an AI recommendation
// Jobs come from findings_ingestion which pre-filters by severity and checks for existing enrichment
func (s *Service) ProcessJob(ctx context.Context, job shared.AIEnrichmentJob) error {
	ctx, span := s.tracer.Start(ctx, "process_ai_enrichment_job",
		trace.WithAttributes(
			attribute.String("org.id", job.OrgID),
			attribute.String("trace.id", job.TraceID),
			attribute.String("discovery.id", job.DiscoveryID),
			attribute.String("finding.type", job.FindingType),
			attribute.String("severity", job.Severity),
		),
	)
	defer span.End()

	s.logger.Info("Processing AI enrichment job",
		zap.String("org_id", job.OrgID),
		zap.String("discovery_id", job.DiscoveryID),
		zap.String("severity", job.Severity),
		zap.String("finding_type", job.FindingType),
	)

	// Get prompt (extensible: could map by finding_type in the future)
	prompt := s.getPrompt("recommendation")
	if prompt == "" {
		return fmt.Errorf("prompt 'recommendation' not found")
	}

	// Get response schema (optional - uses "response" key which maps to response_schema.json)
	responseSchema := s.getResponseSchema("response")

	// Build finding context for AI
	findingContext := s.buildJobContext(job)

	// Generate AI recommendation with structured output
	recommendation, err := s.groqClient.GenerateRecommendation(ctx, prompt, findingContext, responseSchema)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to generate recommendation: %w", err)
	}

	s.logger.Info("AI recommendation generated",
		zap.String("finding_type", job.FindingType),
		zap.Int("recommendation_length", len(recommendation)),
	)

	// Publish enrichment to stream
	return s.publishEnrichment(ctx, job, recommendation, "recommendation")
}

// getPrompt returns the prompt content for the given name
func (s *Service) getPrompt(name string) string {
	return s.prompts[name]
}

// buildJobContext creates a context string from the AI enrichment job for the AI
func (s *Service) buildJobContext(job shared.AIEnrichmentJob) string {
	var sb strings.Builder

	sb.WriteString("## Security Finding\n\n")

	sb.WriteString(fmt.Sprintf("**Type:** %s\n", job.FindingType))
	sb.WriteString(fmt.Sprintf("**Severity:** %s\n", job.Severity))
	sb.WriteString(fmt.Sprintf("**Title:** %s\n", job.Title))
	sb.WriteString(fmt.Sprintf("**Scanner:** %s\n", job.Source))

	if job.Description != "" {
		sb.WriteString(fmt.Sprintf("\n**Description:**\n%s\n", job.Description))
	}

	// Include all metadata dynamically (different scanners have different fields)
	if len(job.Metadata) > 0 {
		sb.WriteString("\n**Additional Details:**\n")

		for key, value := range job.Metadata {
			// Format value based on type
			sb.WriteString(fmt.Sprintf("- %s: %s\n", key, formatMetadataValue(value)))
		}
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
		// Truncate very long strings to avoid token overflow
		if len(v) > 2000 {
			return v[:2000] + "... (truncated)"
		}
		return v
	case []interface{}:
		// Format arrays as comma-separated list
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
		// Format nested objects as JSON-like string
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

// publishEnrichment publishes the AI enrichment to the stream
func (s *Service) publishEnrichment(ctx context.Context, job shared.AIEnrichmentJob, recommendationJSON, promptUsed string) error {
	// Parse JSON response into map for structured storage in MongoDB
	var recommendation map[string]interface{}
	if err := json.Unmarshal([]byte(recommendationJSON), &recommendation); err != nil {
		// If parsing fails, store as raw text in a wrapper object
		s.logger.Warn("Failed to parse AI response as JSON, storing as raw text",
			zap.Error(err),
			zap.String("finding_type", job.FindingType),
		)
		recommendation = map[string]interface{}{
			"raw_response": recommendationJSON,
		}
	}

	enrichment := shared.AIEnrichmentFinding{
		TraceID:        job.TraceID,
		OrgID:          job.OrgID,
		DiscoveryID:    job.DiscoveryID,
		FindingType:    job.FindingType,
		Title:          job.Title,
		Recommendation: recommendation,
		PromptUsed:     promptUsed,
		Model:          s.groqClient.GetModel(),
		Timestamp:      time.Now(),
	}

	// Inject trace context for distributed tracing
	enrichment.TraceContext = telemetry.InjectTraceContext(ctx)

	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamAIEnrichmentResults, enrichment, 5000); err != nil {
		return fmt.Errorf("failed to publish enrichment: %w", err)
	}

	s.logger.Info("Published AI enrichment",
		zap.String("finding_type", job.FindingType),
		zap.String("prompt_used", promptUsed),
		zap.String("model", s.groqClient.GetModel()),
	)

	return nil
}
