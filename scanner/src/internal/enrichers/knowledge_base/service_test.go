package knowledge_base

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/ai"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// validEntry returns a complete entry; mutate edits the decoded map first.
func validEntry(t *testing.T, mutate func(e map[string]any)) json.RawMessage {
	t.Helper()
	e := map[string]any{
		"business": map[string]any{
			"title":     "Missing security header",
			"summary":   "Your website does not tell browsers to block a common kind of attack.",
			"impact":    "Auditors flag it, and it makes other weaknesses easier to abuse.",
			"urgency":   "medium",
			"actions":   []any{"Ask your developer to add the header."},
			"blog_slug": "missing-security-header",
		},
		"technical": map[string]any{
			"title":                     "Missing Content-Security-Policy",
			"vulnerability_explanation": "The server sends no Content-Security-Policy header on HTML responses.",
			"root_cause":                "The web server config has no CSP directive.",
			"impact":                    "Injected scripts run without restriction.",
			"severity":                  map[string]any{"level": "medium", "cvss_estimate": nil, "justification": "Defense in depth only."},
			"affected_components":       []any{"all versions"},
			"remediation_steps":         []any{"Add a report-only CSP header first."},
			"verification_steps":        []any{"curl -I https://example.com | grep -i content-security"},
			"code_examples":             nil,
			"best_practices":            []any{},
			"references":                []any{"https://owasp.org/www-project-secure-headers/", "javascript:alert(1)", " https://example.com/x "},
			"blog_slug":                 "missing-csp-header",
		},
		"metadata": map[string]any{
			"components":       nil,
			"owasp_category":   "A05",
			"estimated_effort": "small",
			"is_exploitable":   false,
			"tags":             []any{"headers"},
		},
	}
	if mutate != nil {
		mutate(e)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func section(e map[string]any, name string) map[string]any { return e[name].(map[string]any) }

func TestValidateEntry(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(e map[string]any)
		wantErr string
	}{
		{"valid", nil, ""},
		{"missing section", func(e map[string]any) { delete(e, "business") }, "business.title"},
		{"short summary", func(e map[string]any) { section(e, "business")["summary"] = "Bad." }, "business.summary"},
		{"unknown urgency", func(e map[string]any) { section(e, "business")["urgency"] = "asap" }, "business.urgency"},
		{"no actions", func(e map[string]any) { section(e, "business")["actions"] = []any{} }, "business.actions"},
		{"blank slug", func(e map[string]any) { section(e, "business")["blog_slug"] = " " }, "business.blog_slug"},
		{"short list items are fine", func(e map[string]any) {
			section(e, "technical")["verification_steps"] = []any{"Retest."}
			section(e, "technical")["blog_slug"] = "jquery-3.5_xss"
		}, ""},
		{"unknown severity", func(e map[string]any) {
			section(section(e, "technical"), "severity")["level"] = "severe"
		}, "technical.severity.level"},
		{"empty remediation step", func(e map[string]any) {
			section(e, "technical")["remediation_steps"] = []any{"   "}
		}, "technical.remediation_steps[0]"},
		{"unknown effort", func(e map[string]any) { section(e, "metadata")["estimated_effort"] = "huge" }, "metadata.estimated_effort"},
		{"missing is_exploitable", func(e map[string]any) { delete(section(e, "metadata"), "is_exploitable") }, "metadata.is_exploitable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEntry(validEntry(t, tt.mutate))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one about %s", err, tt.wantErr)
			}
		})
	}
	if err := ValidateEntry(json.RawMessage(`"text"`)); err == nil {
		t.Error("a JSON string passed validation")
	}
}

func TestNormalizeEntry_References(t *testing.T) {
	raw := validEntry(t, nil)

	withSearch, err := normalizeEntry(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	got := section(withSearch, "technical")["references"]
	want := []any{"https://owasp.org/www-project-secure-headers/", "https://example.com/x"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("references with search = %v, want %v", got, want)
	}

	withoutSearch, err := normalizeEntry(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	if refs := section(withoutSearch, "technical")["references"]; refs != nil {
		t.Errorf("references without search = %v, want null", refs)
	}
}

func newTestService(t *testing.T, rdb *redis.Client, p ai.Provider) *Service {
	t.Helper()
	s, err := NewService(rdb, staticProvider{p}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestComposeSystemPrompt(t *testing.T) {
	s := newTestService(t, nil, nil)

	with := s.composeSystemPrompt(true)
	without := s.composeSystemPrompt(false)
	for _, p := range []string{with, without} {
		if !strings.HasPrefix(p, "You are a cybersecurity expert") || !strings.Contains(p, "generate_kb_entry") {
			t.Errorf("prompt lacks the core rules or the tool instruction:\n%s", p)
		}
	}
	if !strings.Contains(with, "## Web Search") || !strings.Contains(with, "web search results") {
		t.Error("prompt with web search lacks the search section")
	}
	if strings.Contains(strings.ToLower(without), "search") {
		t.Error("prompt without web search mentions searching")
	}
	if !strings.Contains(without, "Set **references** to null") {
		t.Error("prompt without web search does not ask for null references")
	}
}

type staticProvider struct{ p ai.Provider }

func (s staticProvider) Provider(context.Context) (ai.Provider, error) { return s.p, nil }

type fakeProvider struct {
	caps     ai.Capabilities
	result   ai.Result
	got      ai.Request
	deadline time.Time
}

func (f *fakeProvider) Generate(ctx context.Context, req ai.Request) (ai.Result, error) {
	f.got = req
	f.deadline, _ = ctx.Deadline()
	return f.result, nil
}
func (f *fakeProvider) Capabilities() ai.Capabilities { return f.caps }
func (f *fakeProvider) Model() string                 { return "fake-model" }

var testJob = shared.KBGenerationJob{FindingType: "missing-csp", Severity: "medium", Title: "No CSP"}

// These outcomes stop before publishing, so no Redis is needed: a nil client
// would panic if the service tried.
func TestProcessJob_NoEntryWithoutUsableOutput(t *testing.T) {
	tests := []struct {
		name    string
		result  ai.Result
		wantErr string
	}{
		{"refused", ai.Result{Outcome: ai.OutcomeRefused, RefusalCategory: "cyber"}, `refused (category "cyber")`},
		{"truncated", ai.Result{Outcome: ai.OutcomeTruncated}, "outcome truncated"},
		{"no output", ai.Result{Outcome: ai.OutcomeNoOutput}, "outcome no_output"},
		{"invalid entry", ai.Result{Outcome: ai.OutcomeOK, JSON: json.RawMessage(`{"business":{}}`)}, "invalid KB entry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &fakeProvider{caps: ai.Capabilities{WebSearch: true, StrictSchema: true}, result: tt.result}
			err := newTestService(t, nil, p).ProcessJob(context.Background(), testJob)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestProcessJob_RequestFollowsCapabilities(t *testing.T) {
	p := &fakeProvider{caps: ai.Capabilities{WebSearch: false}, result: ai.Result{Outcome: ai.OutcomeNoOutput}}
	_ = newTestService(t, nil, p).ProcessJob(context.Background(), testJob)

	if p.got.WebSearch || strings.Contains(strings.ToLower(p.got.System), "search") {
		t.Error("request asks for web search from a provider without it")
	}
	if p.got.Schema == nil || p.got.Schema.Name != kbToolName || p.got.MaxOutputTokens != kbMaxOutputTokens {
		t.Errorf("request = %+v", p.got)
	}
	if !strings.Contains(p.got.User, "<scanner_title>No CSP</scanner_title>") {
		t.Errorf("user prompt = %q", p.got.User)
	}
}

func TestProcessJob_GenerationHasOneDeadline(t *testing.T) {
	p := &fakeProvider{result: ai.Result{Outcome: ai.OutcomeNoOutput}}
	start := time.Now()
	_ = newTestService(t, nil, p).ProcessJob(context.Background(), testJob)

	if p.deadline.IsZero() {
		t.Fatal("Generate ran without a deadline")
	}
	if left := p.deadline.Sub(start); left > kbGenerateTimeout+time.Second || left < kbGenerateTimeout-time.Minute {
		t.Errorf("deadline in %s, want about %s", left, kbGenerateTimeout)
	}
}

func TestProcessJob_PublishesValidatedEntry(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_REDIS_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	ctx := context.Background()

	job := testJob
	job.FindingType = fmt.Sprintf("kb-test-%d", time.Now().UnixNano())
	p := &fakeProvider{
		caps:   ai.Capabilities{WebSearch: false},
		result: ai.Result{Outcome: ai.OutcomeOK, Model: "claude-sonnet-5-5", JSON: validEntry(t, nil)},
	}
	if err := newTestService(t, rdb, p).ProcessJob(ctx, job); err != nil {
		t.Fatal(err)
	}

	msgs, err := rdb.XRevRangeN(ctx, shared.StreamKBGenerationResults, "+", "-", 20).Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		var res shared.KBGenerationResult
		if err := json.Unmarshal([]byte(m.Values["data"].(string)), &res); err != nil || res.FindingType != job.FindingType {
			continue
		}
		rdb.XDel(ctx, shared.StreamKBGenerationResults, m.ID)
		if res.Model != "claude-sonnet-5-5" {
			t.Errorf("model = %q", res.Model)
		}
		if refs := section(res.Entry, "technical")["references"]; refs != nil {
			t.Errorf("references = %v, want null without web search", refs)
		}
		return
	}
	t.Fatal("no KB result published")
}
