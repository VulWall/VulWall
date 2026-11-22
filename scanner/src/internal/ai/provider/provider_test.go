package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/ai"
	"github.com/VulWall/VulWall/scanner/src/internal/ai/anthropic"
	"go.uber.org/zap"
)

type configs struct{ cfg ai.Config }

func (c *configs) Load(context.Context) (ai.Config, error) { return c.cfg, nil }

func TestNew(t *testing.T) {
	if _, err := New(ai.Config{Provider: "anthropic"}, zap.NewNop()); !errors.Is(err, ErrDisabled) {
		t.Errorf("no key: err = %v, want ErrDisabled", err)
	}
	if _, err := New(ai.Config{Provider: "openai", APIKey: "k"}, zap.NewNop()); err == nil {
		t.Error("unknown provider accepted")
	}
	p, err := New(ai.Config{Provider: "anthropic", APIKey: "k"}, zap.NewNop())
	if err != nil || p.Model() != anthropic.DefaultModel {
		t.Errorf("provider = %v, err = %v", p, err)
	}
}

func TestResolverReadsConfigOnEveryCall(t *testing.T) {
	src := &configs{ai.Config{Provider: "anthropic", APIKey: "k", Model: "claude-sonnet-5-5"}}
	r := NewResolver(src, zap.NewNop())
	ctx := context.Background()

	first, err := r.Provider(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := r.Provider(ctx); again != first {
		t.Error("same config built a new provider")
	}

	src.cfg.Model = "claude-opus-5-5"
	changed, err := r.Provider(ctx)
	if err != nil || changed.Model() != "claude-opus-5-5" {
		t.Errorf("after a model change: %v, %v", changed, err)
	}

	src.cfg.APIKey = ""
	if _, err := r.Provider(ctx); !errors.Is(err, ErrDisabled) {
		t.Errorf("after removing the key: err = %v", err)
	}
}

func TestEnvSource(t *testing.T) {
	t.Setenv("AI_PROVIDER", " Anthropic ")
	t.Setenv("AI_API_KEY", "k")
	t.Setenv("AI_MODEL", "")
	t.Setenv("AI_BASE_URL", "https://gateway.example")

	cfg, err := ai.EnvSource{}.Load(context.Background())
	want := ai.Config{Provider: "anthropic", APIKey: "k", Model: "", BaseURL: "https://gateway.example"}
	if err != nil || cfg != want {
		t.Errorf("config = %+v, err = %v", cfg, err)
	}
}
