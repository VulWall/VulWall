// Package anthropic is the ai.Provider for Anthropic's Messages API, called
// over plain HTTP.
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

	"github.com/VulWall/VulWall/scanner/src/internal/ai"
	"go.uber.org/zap"
)

const (
	// DefaultModel is used when AI_MODEL is empty.
	DefaultModel = "claude-sonnet-5-5"

	// DefaultBaseURL is used when AI_BASE_URL is empty.
	DefaultBaseURL = "https://api.anthropic.com"

	// apiVersion matches the version the current Anthropic SDKs send. On it,
	// temperature, top_p and top_k are rejected, so the request has none.
	apiVersion = "2026-10-21"

	// defaultMaxTokens applies when the request sets no limit. Thinking counts
	// against it, and it keeps a non-streaming call within the HTTP timeout.
	defaultMaxTokens = 16000

	// effort is sent only to models in effortModels. Medium suits research
	// with tool calls.
	effort = "medium"

	// maxRetries and initialBackoff space retries of 429/529/5xx past the
	// one-minute rate-limit window: 15s, 30s, 60s, 120s.
	maxRetries     = 4
	initialBackoff = 15 * time.Second

	// maxContinuations caps pause_turn resumes so a runaway server-tool loop
	// cannot bill without end.
	maxContinuations = 5

	// webSearchMaxUses bounds the cost ($10 per 1000 searches) and latency of
	// one generation.
	webSearchMaxUses = 5

	// maxResponseBytes bounds one response; web search results are large.
	maxResponseBytes = 4 << 20

	requestTimeout = 10 * time.Minute
)

// currentModels take web_search_20260209 (dynamic filtering) and
// output_config.effort. Other model IDs get web_search_20250305 and no
// effort, which every Claude model accepts. Matched by prefix.
var currentModels = []string{
	"claude-fable-", "claude-mythos-",
	"claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
	"claude-sonnet-5", "claude-sonnet-4-6",
}

// effortOnlyModels take effort but only the basic web search tool.
var effortOnlyModels = []string{"claude-haiku-5", "claude-opus-4-5"}

func hasPrefix(model string, prefixes []string) bool {
	model = strings.TrimPrefix(model, "anthropic.")
	for _, p := range prefixes {
		if strings.HasPrefix(model, p) {
			return true
		}
	}
	return false
}

func webSearchToolType(model string) string {
	if hasPrefix(model, currentModels) {
		return "web_search_20260209"
	}
	return "web_search_20250305"
}

func acceptsEffort(model string) bool {
	return hasPrefix(model, currentModels) || hasPrefix(model, effortOnlyModels)
}

// Client implements ai.Provider.
type Client struct {
	apiKey     string
	model      string
	url        string
	httpClient *http.Client
	logger     *zap.Logger
	// backoff returns the wait before retry attempt n (n >= 1). Tests set it.
	backoff func(n int) time.Duration
}

var _ ai.Provider = (*Client)(nil)

// New returns a client for model (DefaultModel when empty) at baseURL
// (DefaultBaseURL when empty).
func New(apiKey, model, baseURL string, logger *zap.Logger) *Client {
	if model == "" {
		model = DefaultModel
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		apiKey:     apiKey,
		model:      model,
		url:        strings.TrimRight(baseURL, "/") + "/v1/messages",
		httpClient: newHTTPClient(),
		logger:     logger,
		backoff:    func(n int) time.Duration { return initialBackoff * time.Duration(1<<(n-1)) },
	}
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		// A non-streaming response arrives in one piece after all thinking,
		// searches and output, so the header wait is the whole generation.
		ResponseHeaderTimeout: requestTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	return &http.Client{Timeout: requestTimeout, Transport: transport}
}

// Model implements ai.Provider.
func (c *Client) Model() string { return c.model }

// Capabilities implements ai.Provider.
func (c *Client) Capabilities() ai.Capabilities {
	return ai.Capabilities{WebSearch: true, StrictSchema: true}
}

// --- wire types ---------------------------------------------------------------

type message struct {
	Role string `json:"role"`
	// Content is a JSON string for user turns and the response's content
	// array, unchanged, for assistant turns: thinking signatures, encrypted
	// search results and block types this client does not know must go back
	// as received. The encoder only removes whitespace between JSON tokens
	// (the API sends none); string contents are never re-escaped.
	Content json.RawMessage `json:"content"`
}

type tool struct {
	Type        string          `json:"type,omitempty"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Strict      bool            `json:"strict,omitempty"`
	MaxUses     int             `json:"max_uses,omitempty"`
}

type toolChoice struct {
	Type string `json:"type"`
}

type outputConfig struct {
	Effort string `json:"effort,omitempty"`
}

type request struct {
	Model        string        `json:"model"`
	MaxTokens    int           `json:"max_tokens"`
	System       string        `json:"system,omitempty"`
	Messages     []message     `json:"messages"`
	Tools        []tool        `json:"tools,omitempty"`
	ToolChoice   *toolChoice   `json:"tool_choice,omitempty"`
	OutputConfig *outputConfig `json:"output_config,omitempty"`
}

type response struct {
	Model       string          `json:"model"`
	StopReason  string          `json:"stop_reason"`
	StopDetails *stopDetails    `json:"stop_details"`
	Content     json.RawMessage `json:"content"`
	Usage       struct {
		InputTokens   int `json:"input_tokens"`
		OutputTokens  int `json:"output_tokens"`
		ServerToolUse *struct {
			WebSearchRequests int `json:"web_search_requests"`
		} `json:"server_tool_use"`
	} `json:"usage"`
}

type stopDetails struct {
	Category *string `json:"category"`
}

// block is the part of a content block this client reads. Thinking,
// server-tool and search-result blocks are skipped by Type.
type block struct {
	Type  string          `json:"type"`
	Name  string          `json:"name"`
	Text  string          `json:"text"`
	Input json.RawMessage `json:"input"`
}

// APIError is a non-200 response from the API.
type APIError struct {
	Status  int
	Type    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("anthropic API HTTP %d: %s (type: %s)", e.Status, e.Message, e.Type)
	}
	return fmt.Sprintf("anthropic API HTTP %d", e.Status)
}

// --- generation -----------------------------------------------------------------

// Generate implements ai.Provider. With a Schema, the model gets a strict
// tool of that name and tool_choice auto (current models reject a forced
// tool_choice), so the result is read from the tool call; a turn that ends
// without the call gets one follow-up that asks for it.
func (c *Client) Generate(ctx context.Context, req ai.Request) (ai.Result, error) {
	if c.apiKey == "" {
		return ai.Result{}, errors.New("anthropic API key not configured")
	}
	user, err := marshal(req.User)
	if err != nil {
		return ai.Result{}, err
	}
	body := request{
		Model:     c.model,
		MaxTokens: req.MaxOutputTokens,
		System:    req.System,
		Messages:  []message{{Role: "user", Content: user}},
	}
	if body.MaxTokens <= 0 {
		body.MaxTokens = defaultMaxTokens
	}
	if acceptsEffort(c.model) {
		body.OutputConfig = &outputConfig{Effort: effort}
	}
	if req.WebSearch {
		body.Tools = append(body.Tools, tool{Type: webSearchToolType(c.model), Name: "web_search", MaxUses: webSearchMaxUses})
	}
	if req.Schema != nil {
		body.Tools = append(body.Tools, tool{
			Name:        req.Schema.Name,
			Description: req.Schema.Description,
			InputSchema: req.Schema.JSON,
			Strict:      true,
		})
	}
	if len(body.Tools) > 0 {
		body.ToolChoice = &toolChoice{Type: "auto"}
	}

	result := ai.Result{Model: c.model}
	continuations, nudged := 0, false
	for {
		resp, err := c.send(ctx, body)
		if err != nil {
			return result, err
		}
		if resp.Model != "" {
			result.Model = resp.Model
		}
		result.Usage.InputTokens += resp.Usage.InputTokens
		result.Usage.OutputTokens += resp.Usage.OutputTokens
		if resp.Usage.ServerToolUse != nil {
			result.WebSearches += resp.Usage.ServerToolUse.WebSearchRequests
		}

		// A refusal can come with empty or partial content, so it is checked
		// before anything is read. It is final: the same request would be
		// declined again.
		if resp.StopReason == "refusal" {
			result.Outcome = ai.OutcomeRefused
			if resp.StopDetails != nil && resp.StopDetails.Category != nil {
				result.RefusalCategory = *resp.StopDetails.Category
			}
			c.logger.Warn("AI request refused",
				zap.String("model", result.Model),
				zap.String("category", result.RefusalCategory))
			return result, nil
		}
		// A truncated tool call holds incomplete JSON; never use it.
		if resp.StopReason == "max_tokens" || resp.StopReason == "model_context_window_exceeded" {
			result.Outcome = ai.OutcomeTruncated
			return result, nil
		}

		var blocks []block
		if err := json.Unmarshal(resp.Content, &blocks); err != nil {
			return result, fmt.Errorf("decode response content: %w", err)
		}

		if req.Schema != nil {
			for _, b := range blocks {
				if b.Type == "tool_use" && b.Name == req.Schema.Name && len(b.Input) > 0 && string(b.Input) != "null" {
					result.JSON = b.Input
					result.Outcome = ai.OutcomeOK
					return result, nil
				}
			}
		}

		// pause_turn: the server-side tool loop stopped early. Send the turn
		// back unchanged and the API resumes it; no user message is added.
		if resp.StopReason == "pause_turn" {
			if continuations >= maxContinuations {
				return result, fmt.Errorf("turn still paused after %d continuations", maxContinuations)
			}
			continuations++
			body.Messages = append(body.Messages, message{Role: "assistant", Content: resp.Content})
			continue
		}

		if req.Schema == nil {
			var text strings.Builder
			for _, b := range blocks {
				if b.Type == "text" {
					text.WriteString(b.Text)
				}
			}
			result.Text = strings.TrimSpace(text.String())
			result.Outcome = ai.OutcomeOK
			if result.Text == "" {
				result.Outcome = ai.OutcomeNoOutput
			}
			return result, nil
		}

		// The turn ended without the schema tool call. Ask once, appending to
		// the conversation so the research and thinking so far stay valid.
		if nudged {
			result.Outcome = ai.OutcomeNoOutput
			return result, nil
		}
		nudged = true
		c.logger.Info("AI turn ended without the structured output call, asking again",
			zap.String("stop_reason", resp.StopReason), zap.String("tool", req.Schema.Name))
		nudge, err := marshal(fmt.Sprintf(
			"You ended your turn without calling the %s tool. Call %s now with the complete entry. Do not answer in text.",
			req.Schema.Name, req.Schema.Name))
		if err != nil {
			return result, err
		}
		body.Messages = append(body.Messages,
			message{Role: "assistant", Content: resp.Content},
			message{Role: "user", Content: nudge})
	}
}

// send performs one Messages request, retrying rate limits, overloads,
// gateway errors and network timeouts with backoff.
func (c *Client) send(ctx context.Context, body request) (*response, error) {
	payload, err := marshal(body)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := c.backoff(attempt)
			c.logger.Warn("Retrying AI request", zap.Int("attempt", attempt), zap.Duration("backoff", wait), zap.Error(lastErr))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		resp, err := c.do(ctx, payload)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil || !retryable(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) do(ctx context.Context, payload []byte) (*response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", apiVersion)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		apiErr := &APIError{Status: httpResp.StatusCode}
		var e struct {
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil {
			apiErr.Type, apiErr.Message = e.Error.Type, e.Error.Message
		}
		return nil, apiErr
	}
	var resp response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// retryable reports whether a later attempt can succeed: 429 rate limit,
// 529 overloaded, gateway errors, and network timeouts or resets. 500 is not
// retried: the request may have run.
func retryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
			return true
		}
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "connection reset")
}

// marshal encodes v without HTML escaping, so text in prompts and echoed
// content goes out as written.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
