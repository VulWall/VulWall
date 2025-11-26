package groq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

const (
	// DefaultModel is the default Groq model to use
	DefaultModel = "llama-3.3-70b-versatile"

	// API endpoint
	groqAPIURL = "https://api.groq.com/openai/v1/chat/completions"

	// Retry configuration
	maxRetries    = 3
	initialBackoff = 1 * time.Second
)

// Client is a Groq API client with retry logic
type Client struct {
	apiKey     string
	httpClient *http.Client
	logger     *zap.Logger
	model      string
}

// ChatRequest represents a Groq chat completion request
type ChatRequest struct {
	Model               string          `json:"model"`
	Messages            []Message       `json:"messages"`
	Temperature         float64         `json:"temperature,omitempty"`
	MaxCompletionTokens int             `json:"max_completion_tokens,omitempty"`
	ResponseFormat      *ResponseFormat `json:"response_format,omitempty"`
}

// ResponseFormat specifies the output format for structured responses
type ResponseFormat struct {
	Type       string      `json:"type"`
	JSONSchema *JSONSchema `json:"json_schema,omitempty"`
}

// JSONSchema defines the schema for structured JSON output
type JSONSchema struct {
	Name   string                 `json:"name"`
	Schema map[string]interface{} `json:"schema"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse represents a Groq chat completion response
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Choice represents a response choice
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage represents token usage
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ErrorResponse represents a Groq API error
type ErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// NewClient creates a new Groq API client
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
		ResponseHeaderTimeout: 30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
	}

	transport.DialContext = (&net.Dialer{
		Timeout: 5 * time.Second,
	}).DialContext

	return &http.Client{
		Timeout:   45 * time.Second, // LLM responses can be slow
		Transport: transport,
	}
}

// GenerateRecommendation generates an AI recommendation for a security finding
func (c *Client) GenerateRecommendation(ctx context.Context, systemPrompt, findingContext string, responseSchema *JSONSchema) (string, error) {
	if c.apiKey == "" {
		return "", fmt.Errorf("groq API key not configured")
	}

	request := ChatRequest{
		Model: c.model,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: findingContext},
		},
		Temperature:         0.7, // Balanced between creativity and consistency
		MaxCompletionTokens: 4096,
	}

	// Add response format if schema provided
	if responseSchema != nil {
		request.ResponseFormat = &ResponseFormat{
			Type:       "json_schema",
			JSONSchema: responseSchema,
		}
	}

	response, err := c.chatCompletionWithRetry(ctx, request)
	if err != nil {
		return "", err
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	c.logger.Debug("AI recommendation generated",
		zap.String("model", c.model),
		zap.Int("prompt_tokens", response.Usage.PromptTokens),
		zap.Int("completion_tokens", response.Usage.CompletionTokens),
	)

	return response.Choices[0].Message.Content, nil
}

// chatCompletionWithRetry performs a chat completion request with exponential backoff retry
func (c *Client) chatCompletionWithRetry(ctx context.Context, request ChatRequest) (*ChatResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Backoff delay: 0s, 1s, 2s, 4s
		if attempt > 0 {
			backoff := initialBackoff * time.Duration(1<<(attempt-1))
			c.logger.Debug("Retrying Groq API request",
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

		c.logger.Warn("Groq API request failed, will retry",
			zap.Int("attempt", attempt),
			zap.Error(err),
		)
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// doRequest performs a single HTTP request to the Groq API
func (c *Client) doRequest(ctx context.Context, request ChatRequest) (*ChatResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", groqAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
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

	var response ChatResponse
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

	// Check net.Error interface
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}

	// HTTP 5xx errors are retryable
	if strings.Contains(errStr, "HTTP 5") {
		return true
	}

	// HTTP 429 (rate limit) is retryable
	if strings.Contains(errStr, "HTTP 429") {
		return true
	}

	// Don't retry 4xx client errors (except 429)
	return false
}

// GetModel returns the model being used
func (c *Client) GetModel() string {
	return c.model
}
