// Package ai is the provider-neutral contract for the scanner's AI calls.
// Callers build a Request, get a Provider from a Resolver, and read a Result;
// provider adapters live in subpackages (anthropic) and are built by
// provider.New.
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
)

// ProviderAnthropic is the only provider in this release, and the default.
const ProviderAnthropic = "anthropic"

// Schema asks the provider for JSON output that matches a JSON Schema.
type Schema struct {
	Name        string
	Description string
	JSON        json.RawMessage
}

// Request is one generation: a system prompt, one user message and the
// output limit. Schema is optional; WebSearch is honoured only when the
// provider's Capabilities allow it.
type Request struct {
	System          string
	User            string
	MaxOutputTokens int
	Schema          *Schema
	WebSearch       bool
}

// Outcome says how a generation ended when the call itself succeeded.
type Outcome string

const (
	OutcomeOK        Outcome = "ok"
	OutcomeRefused   Outcome = "refused"   // the model or a safety classifier declined
	OutcomeTruncated Outcome = "truncated" // the output limit was hit
	OutcomeNoOutput  Outcome = "no_output" // no text, or no schema output after the retry
)

// Usage is the token count summed over every request the generation made.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// Result is the output of a generation. Text is set without a Schema, JSON
// with one; both are empty unless Outcome is OutcomeOK.
type Result struct {
	Text            string
	JSON            json.RawMessage
	Model           string
	Outcome         Outcome
	RefusalCategory string // set when Outcome is OutcomeRefused and the provider names one
	Usage           Usage
	WebSearches     int
}

// Capabilities are the optional features a provider and model support.
type Capabilities struct {
	WebSearch    bool
	StrictSchema bool
}

// Provider generates text or JSON. Transport and API failures are errors;
// model behaviour (refusal, truncation, no output) is a Result Outcome.
type Provider interface {
	Generate(ctx context.Context, req Request) (Result, error)
	Capabilities() Capabilities
	Model() string
}

// Config selects and authenticates a provider. An empty Model or BaseURL
// means the provider's default.
type Config struct {
	Provider string
	APIKey   string
	Model    string
	BaseURL  string
}

// Enabled reports whether AI is configured at all.
func (c Config) Enabled() bool { return c.APIKey != "" }

// String masks the API key, so logging a Config never leaks it.
func (c Config) String() string {
	key := ""
	if c.APIKey != "" {
		key = "***"
	}
	return fmt.Sprintf("{Provider:%s APIKey:%s Model:%s BaseURL:%s}", c.Provider, key, c.Model, c.BaseURL)
}

// GoString masks the API key for %#v too.
func (c Config) GoString() string { return "ai.Config" + c.String() }

// ValidateBaseURL accepts an empty value (the provider's own API), an https
// URL, or an http URL whose host is local: loopback, a private or link-local
// address, localhost, a .local/.internal/.localhost name, or a single-label
// name such as a compose service. Plain http to anything else would send the
// API key and the prompts across the internet unencrypted.
func ValidateBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("AI_BASE_URL %q is not an absolute URL", raw)
	}
	if u.User != nil {
		return fmt.Errorf("AI_BASE_URL must not contain credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLocalHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("AI_BASE_URL %q uses http to a non-local host; use https", raw)
	default:
		return fmt.Errorf("AI_BASE_URL %q must use https (or http to a local host)", raw)
	}
}

func isLocalHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "localhost" || !strings.Contains(host, ".") ||
		strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal")
}

// ConfigSource returns the current AI configuration. It is read on every
// call, so a source backed by stored settings takes effect without a restart.
type ConfigSource interface {
	Load(ctx context.Context) (Config, error)
}

// EnvSource reads AI_PROVIDER, AI_API_KEY, AI_MODEL and AI_BASE_URL.
type EnvSource struct{}

// Load implements ConfigSource.
func (EnvSource) Load(context.Context) (Config, error) {
	return Config{
		Provider: strings.ToLower(strings.TrimSpace(config.GetEnv(config.EnvAIProvider, ProviderAnthropic))),
		APIKey:   strings.TrimSpace(config.GetEnv(config.EnvAIAPIKey, "")),
		Model:    strings.TrimSpace(config.GetEnv(config.EnvAIModel, "")),
		BaseURL:  strings.TrimSpace(config.GetEnv(config.EnvAIBaseURL, "")),
	}, nil
}
