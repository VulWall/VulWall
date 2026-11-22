// Package provider builds an ai.Provider from an ai.Config.
package provider

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/VulWall/VulWall/scanner/src/internal/ai"
	"github.com/VulWall/VulWall/scanner/src/internal/ai/anthropic"
	"go.uber.org/zap"
)

// ErrDisabled is returned when no API key is configured.
var ErrDisabled = errors.New("AI is not configured")

// New returns the provider cfg selects.
func New(cfg ai.Config, logger *zap.Logger) (ai.Provider, error) {
	if !cfg.Enabled() {
		return nil, ErrDisabled
	}
	switch cfg.Provider {
	case "", ai.ProviderAnthropic:
		return anthropic.New(cfg.APIKey, cfg.Model, cfg.BaseURL, logger), nil
	default:
		return nil, fmt.Errorf("unknown AI provider %q (supported: %s)", cfg.Provider, ai.ProviderAnthropic)
	}
}

// Resolver reads the configuration on every call and keeps the provider
// built from it until the configuration changes.
type Resolver struct {
	source ai.ConfigSource
	logger *zap.Logger

	mu       sync.Mutex
	cfg      ai.Config
	provider ai.Provider
}

// NewResolver returns a Resolver over source.
func NewResolver(source ai.ConfigSource, logger *zap.Logger) *Resolver {
	return &Resolver{source: source, logger: logger}
}

// Provider returns the provider for the current configuration, or
// ErrDisabled.
func (r *Resolver) Provider(ctx context.Context) (ai.Provider, error) {
	cfg, err := r.source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AI config: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.provider != nil && cfg == r.cfg {
		return r.provider, nil
	}
	p, err := New(cfg, r.logger)
	if err != nil {
		return nil, err
	}
	r.cfg, r.provider = cfg, p
	return p, nil
}
