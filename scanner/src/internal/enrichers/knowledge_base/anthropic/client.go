package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultModel is the default Anthropic model to use
	DefaultModel = "claude-sonnet-4-6"

	// API endpoint
	anthropicAPIURL = "https://api.anthropic.com/v1/messages"

	// API version header
	anthropicVersion = "2023-06-01"

	// Retry configuration — backoff must exceed the 1-minute token rate limit
	// window (30K input tokens/min on Tier 1). A single KB request with web
	// search can use 25-55K input tokens, so we need retries spaced far enough
	// apart for the per-minute budget to reset.
	maxRetries     = 4
	initialBackoff = 15 * time.Second

	// maxAgenticLoopIterations caps pause_turn continuation loops to prevent
	// runaway billing. In practice web search completes in one turn; this guards
	// against edge cases.
	maxAgenticLoopIterations = 5
)

// Client is an Anthropic API client with retry logic
type Client struct {
	apiKey     string
	httpClient *http.Client
	logger     *zap.Logger
	model      string
}

// MessagesRequest represents an Anthropic Messages API request
type MessagesRequest struct {
	Model       string      `json:"model"`
	MaxTokens   int         `json:"max_tokens"`
	System      string      `json:"system,omitempty"`
	Messages    []Message   `json:"messages"`
	Temperature float64     `json:"temperature,omitempty"`
	Tools       []Tool      `json:"tools,omitempty"`
	ToolChoice  *ToolChoice `json:"tool_choice,omitempty"`
}

// Message represents a chat message. Content is an interface{} so it can hold
// either a plain string (user turn) or a slice of ContentBlock (assistant turn
// passed back in a multi-turn continuation after pause_turn).
type Message struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

// Tool represents an Anthropic tool definition. For standard tools (like
// generate_kb_entry) only Name, Description, InputSchema, and Strict are used.
// For server-managed tools (like web_search), only Type and Name are required —
// Anthropic's API executes the tool server-side and does not accept InputSchema
// or Strict for server tools.
//
// Strict enables constrained decoding: the API guarantees that the tool Input
// exactly matches InputSchema (no extra properties, no missing required fields).
// Without Strict, the schema is advisory only — the model can add fields outside
// the schema, which is the root cause of unexpected fields appearing in output.
// Use a pointer so that false is also representable; omitempty drops nil (server
// tools like web_search must not send this field at all).
type Tool struct {
	Type        string          `json:"type,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Strict      *bool           `json:"strict,omitempty"`
	MaxUses     int             `json:"max_uses,omitempty"`
}

// ToolChoice instructs the model how to select tools:
//   - type "tool" + name forces a specific tool (guaranteed structured output, prevents web search)
//   - type "auto" lets Claude decide which tool to call (required when web search is present)
//   - type "any" forces Claude to call at least one tool without specifying which
type ToolChoice struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
}

// MessagesResponse represents an Anthropic Messages API response
type MessagesResponse struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Content      []ContentBlock `json:"content"`
	Model        string         `json:"model"`
	StopReason   string         `json:"stop_reason"`
	StopSequence *string        `json:"stop_sequence"`
	Usage        Usage          `json:"usage"`
}

// ContentBlock represents a single content block in the response. Multiple
// block types can appear in a single response when web search is active:
//
//   - type "text"                   — plain text from Claude (may include citations)
//   - type "tool_use"               — client-side tool call (our generate_kb_entry)
//   - type "server_tool_use"        — server-side tool invocation (web_search, executed by Anthropic)
//   - type "web_search_tool_result" — results returned to Claude from a server_tool_use
//
// We use json.RawMessage for Input so it round-trips intact when we echo the
// assistant turn back to the API in a pause_turn continuation.
type ContentBlock struct {
	Type string `json:"type"`

	// text blocks
	Text string `json:"text,omitempty"`

	// tool_use and server_tool_use blocks
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// web_search_tool_result blocks
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
}

// Usage represents token usage. ServerToolUse tracks web search request counts
// for observability; it is nil when no server tools are used.
type Usage struct {
	InputTokens  int            `json:"input_tokens"`
	OutputTokens int            `json:"output_tokens"`
	ServerToolUse *ServerToolUse `json:"server_tool_use,omitempty"`
}

// ServerToolUse contains counts of server-side tool invocations.
type ServerToolUse struct {
	WebSearchRequests int `json:"web_search_requests"`
}

// ErrorResponse represents an Anthropic API error
type ErrorResponse struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// NewClient creates a new Anthropic API client
func NewClient(apiKey string, model string, logger *zap.Logger) *Client {
	if model == "" {
		model = DefaultModel
	}

	return &Client{
		apiKey:     apiKey,
		httpClient: createHTTPClient(),
		logger:     logger,
		model:      model,
	}
}

// createHTTPClient creates an optimized HTTP client for LLM API calls
func createHTTPClient() *http.Client {
	transport := &http.Transport{
		// Web search can add significant latency — Anthropic executes searches
		// server-side and multiple searches may occur before the final response.
		ResponseHeaderTimeout: 120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
	}

	transport.DialContext = (&net.Dialer{
		Timeout: 5 * time.Second,
	}).DialContext

	return &http.Client{
		Timeout:   180 * time.Second, // Extended: web search adds server-side latency
		Transport: transport,
	}
}

const (
	// kbToolName is the tool name used for structured KB entry generation.
	// Changing this invalidates the grammar cache on Anthropic's side.
	kbToolName = "generate_kb_entry"

	// kbToolDescription tells Claude what the tool produces.
	kbToolDescription = "Generate a structured knowledge base entry for a security vulnerability finding, " +
		"covering business impact, technical details, and metadata."

	// webSearchToolType is the versioned type identifier for Anthropic's
	// server-side web search tool. This is a server-managed tool — Anthropic
	// executes searches on our behalf; we do not need to handle tool_result
	// responses for it. The version is pinned to avoid unexpected behavior
	// changes from automatic upgrades.
	webSearchToolType = "web_search_20250305"

	// webSearchToolName is the required name for the web search tool.
	webSearchToolName = "web_search"

	// webSearchMaxUses caps the number of searches per KB entry generation to
	// bound cost ($10 / 1000 searches) and latency. CVE research rarely needs
	// more than 5 searches (CVE page, vendor advisory, NVD, patch notes, OWASP).
	webSearchMaxUses = 5
)

// boolPtr returns a pointer to b. Used to set optional boolean fields in API
// structs where nil (omitempty) means "omit" and false is a distinct value.
func boolPtr(b bool) *bool { return &b }

// GenerateKBEntry generates a knowledge base entry for a finding type using
// structured output (tool_use with strict: true) and optionally web search.
//
// When web search is active, Claude may perform up to webSearchMaxUses searches
// before calling generate_kb_entry — all executed server-side by Anthropic. We
// never need to handle tool_result for web_search ourselves.
//
// The inputSchema must be valid JSON Schema bytes from response_schema.json.
// The returned string is guaranteed-valid JSON matching that schema, ready for
// direct json.Unmarshal by the caller.
//
// strict: true on the generate_kb_entry tool enables constrained decoding at the
// API level. This is the critical difference between advisory schema enforcement
// (where the model CAN emit extra fields) and guaranteed enforcement (where the
// API rejects any output that does not match the schema exactly). Without this,
// additionalProperties: false in the schema is treated as a hint only.
func (c *Client) GenerateKBEntry(ctx context.Context, systemPrompt, findingContext string, inputSchema json.RawMessage) (string, error) {
	if c.apiKey == "" {
		return "", fmt.Errorf("anthropic API key not configured")
	}

	// tool_choice "any" forces Claude to call at least one tool while letting it
	// choose which. This allows web_search first (server-side), then
	// generate_kb_entry for structured output. Forcing tool_choice to a specific
	// tool would prevent web search; "auto" would allow Claude to skip tools entirely.
	request := MessagesRequest{
		Model:     c.model,
		MaxTokens: 8192,
		System:    systemPrompt,
		Messages: []Message{
			{Role: "user", Content: findingContext},
		},
		Temperature: 0.3, // Low temperature for consistency across KB entries
		Tools: []Tool{
			{
				// Server-side web search tool. Anthropic executes searches and
				// returns results as web_search_tool_result content blocks.
				// No InputSchema or Strict — this is a server-managed tool;
				// the Anthropic API does not accept those fields for server tools.
				Type:    webSearchToolType,
				Name:    webSearchToolName,
				MaxUses: webSearchMaxUses,
			},
			{
				// Client-side structured output tool. Claude calls this last,
				// after researching, to emit the validated JSON KB entry.
				//
				// Strict: true activates constrained decoding: the API guarantees
				// the tool Input matches InputSchema exactly. Without this, the
				// model treats additionalProperties: false as advisory and can
				// emit extra fields (e.g. cvss_estimate appearing inside metadata).
				Name:        kbToolName,
				Description: kbToolDescription,
				InputSchema: inputSchema,
				Strict:      boolPtr(true),
			},
		},
		ToolChoice: &ToolChoice{
			// "any" forces Claude to call at least one tool (preventing plain-text
			// responses that skip structured output), while letting it choose which
			// tool to call first. Claude will use web_search for research, then
			// call generate_kb_entry for the final structured output.
			Type: "any",
		},
	}

	return c.runAgenticLoop(ctx, request)
}

// runAgenticLoop drives the agentic conversation until Claude calls
// generate_kb_entry or an unrecoverable error occurs.
//
// The loop exists to handle the pause_turn stop reason, which Anthropic uses
// when a long-running turn is paused mid-way. In that case we echo the
// assistant turn back and continue. In practice, web search completes within
// a single turn (stop_reason: end_turn or tool_use), so the loop rarely
// iterates more than once.
func (c *Client) runAgenticLoop(ctx context.Context, request MessagesRequest) (string, error) {
	totalInputTokens := 0
	totalOutputTokens := 0
	totalWebSearches := 0

	for iteration := 0; iteration < maxAgenticLoopIterations; iteration++ {
		response, err := c.messagesWithRetry(ctx, request)
		if err != nil {
			return "", err
		}

		// Accumulate token usage across iterations for observability
		totalInputTokens += response.Usage.InputTokens
		totalOutputTokens += response.Usage.OutputTokens
		if response.Usage.ServerToolUse != nil {
			totalWebSearches += response.Usage.ServerToolUse.WebSearchRequests
		}

		// Check for truncation FIRST, before scanning content blocks. A truncated
		// response may contain a partial tool_use block with incomplete JSON in
		// Input — accepting it would publish a corrupt KB entry.
		if response.StopReason == "max_tokens" {
			return "", fmt.Errorf("response truncated (stop_reason: max_tokens) after %d iterations: consider increasing MaxTokens or simplifying prompt", iteration)
		}

		// Scan the response content for the generate_kb_entry tool_use block.
		// With tool_choice "any", Claude must call at least one tool. It may call
		// web_search first (server-side), then generate_kb_entry for structured output.
		for _, block := range response.Content {
			if block.Type == "tool_use" && block.Name == kbToolName {
				if len(block.Input) == 0 || string(block.Input) == "null" {
					return "", fmt.Errorf("tool_use block has empty or null input")
				}

				c.logger.Info("KB entry generated via structured output",
					zap.String("model", c.model),
					zap.String("stop_reason", response.StopReason),
					zap.Int("iteration", iteration),
					zap.Int("total_input_tokens", totalInputTokens),
					zap.Int("total_output_tokens", totalOutputTokens),
					zap.Int("web_searches", totalWebSearches),
				)

				return string(block.Input), nil
			}
		}

		// pause_turn: Anthropic paused a long-running turn mid-way. Echo the
		// assistant message back to let Claude continue. This is the documented
		// continuation pattern for pause_turn.
		if response.StopReason == "pause_turn" {
			c.logger.Debug("Received pause_turn, continuing agentic loop",
				zap.Int("iteration", iteration),
				zap.Int("web_searches_so_far", totalWebSearches),
			)

			request.Messages = append(request.Messages, Message{
				Role:    "assistant",
				Content: response.Content,
			})
			continue
		}

		// end_turn or tool_use without generate_kb_entry: Claude finished its
		// turn but did not call the structured output tool. This should not
		// happen with a well-crafted system prompt, but we guard defensively.
		if response.StopReason == "end_turn" || response.StopReason == "tool_use" {
			return "", fmt.Errorf("Claude finished (stop_reason: %s) without calling %q — check system prompt instructions", response.StopReason, kbToolName)
		}

		// Unrecognised stop reason — fail fast rather than loop indefinitely.
		return "", fmt.Errorf("unexpected stop_reason %q from Anthropic API", response.StopReason)
	}

	return "", fmt.Errorf("agentic loop exceeded %d iterations without calling %q", maxAgenticLoopIterations, kbToolName)
}

// messagesWithRetry performs a Messages API request with exponential backoff retry
func (c *Client) messagesWithRetry(ctx context.Context, request MessagesRequest) (*MessagesResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Backoff delay: 0s, 15s, 30s, 60s, 120s
		if attempt > 0 {
			backoff := initialBackoff * time.Duration(1<<(attempt-1))
			c.logger.Debug("Retrying Anthropic API request",
				zap.Int("attempt", attempt),
				zap.Duration("backoff", backoff),
			)

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		response, err := c.doRequest(ctx, request)
		if err == nil {
			return response, nil
		}

		lastErr = err

		// Don't retry non-retryable errors
		if !isRetryableError(err) {
			return nil, err
		}

		c.logger.Warn("Anthropic API request failed, will retry",
			zap.Int("attempt", attempt),
			zap.Error(err),
		)
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// doRequest performs a single HTTP request to the Anthropic API
func (c *Client) doRequest(ctx context.Context, request MessagesRequest) (*MessagesResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Web search responses can be large: each search result set may include
	// thousands of tokens of HTML content, citations, and encrypted blobs.
	// 4MB is a safe upper bound that prevents OOM while accommodating the
	// largest realistic responses.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4MB max
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("HTTP %d: %s (type: %s)", resp.StatusCode, errResp.Error.Message, errResp.Error.Type)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var response MessagesResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// isRetryableError determines if an error is retryable
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Network errors
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "TLS handshake timeout") {
		return true
	}

	// Check net.Error interface (including wrapped errors)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	// HTTP gateway/availability errors are retryable (not 500 — could be non-idempotent)
	if strings.Contains(errStr, "HTTP 429") ||
		strings.Contains(errStr, "HTTP 502") ||
		strings.Contains(errStr, "HTTP 503") ||
		strings.Contains(errStr, "HTTP 504") ||
		strings.Contains(errStr, "HTTP 529") { // Anthropic-specific overloaded
		return true
	}

	return false
}

// GetModel returns the model being used
func (c *Client) GetModel() string {
	return c.model
}
