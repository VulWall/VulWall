package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/ai"
	"go.uber.org/zap"
)

// reply is one canned HTTP response.
type reply struct {
	status int
	body   string
}

func ok(stopReason, content string) reply {
	return reply{http.StatusOK, fmt.Sprintf(
		`{"model":"claude-sonnet-5-5","stop_reason":%q,"stop_details":null,"content":%s,`+
			`"usage":{"input_tokens":100,"output_tokens":10,"server_tool_use":{"web_search_requests":1}}}`,
		stopReason, content)}
}

// fakeAPI serves replies in order and records each request.
type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	replies  []reply
	bodies   [][]byte
	headers  []http.Header
	location string // sent as Location with every reply when set
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/v1/messages" {
		f.t.Errorf("path = %s, want /v1/messages", r.URL.Path)
	}
	f.bodies = append(f.bodies, body)
	f.headers = append(f.headers, r.Header.Clone())
	if len(f.replies) == 0 {
		f.t.Errorf("unexpected request %d", len(f.bodies))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	next := f.replies[0]
	f.replies = f.replies[1:]
	if f.location != "" {
		w.Header().Set("Location", f.location)
	}
	w.WriteHeader(next.status)
	_, _ = io.WriteString(w, next.body)
}

// sentRequest is the decoded request body, with message content kept raw.
type sentRequest struct {
	raw       map[string]json.RawMessage
	Model     string `json:"model"`
	MaxTokens int    `json:"max_tokens"`
	Messages  []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Strict  bool   `json:"strict"`
		MaxUses int    `json:"max_uses"`
	} `json:"tools"`
	ToolChoice   *struct{ Type string }   `json:"tool_choice"`
	OutputConfig *struct{ Effort string } `json:"output_config"`
}

func (f *fakeAPI) request(i int) sentRequest {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var r sentRequest
	if err := json.Unmarshal(f.bodies[i], &r); err != nil {
		f.t.Fatalf("request %d: %v", i, err)
	}
	if err := json.Unmarshal(f.bodies[i], &r.raw); err != nil {
		f.t.Fatalf("request %d: %v", i, err)
	}
	return r
}

func (f *fakeAPI) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func newTestClient(t *testing.T, model string, replies ...reply) (*Client, *fakeAPI, *[]int) {
	t.Helper()
	api := &fakeAPI{t: t, replies: replies}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	c := New("test-key", model, srv.URL, zap.NewNop())
	var waits []int
	c.backoff = func(n int) time.Duration { waits = append(waits, n); return time.Millisecond }
	return c, api, &waits
}

var testSchema = &ai.Schema{Name: "generate_kb_entry", Description: "d", JSON: json.RawMessage(`{"type":"object"}`)}

func kbRequest() ai.Request {
	return ai.Request{System: "sys", User: "finding <b>&</b>", MaxOutputTokens: 16000, Schema: testSchema, WebSearch: true}
}

const toolCall = `[{"type":"thinking","thinking":"","signature":"sig=="},` +
	`{"type":"tool_use","id":"toolu_1","name":"generate_kb_entry","input":{"business":{"title":"x"}}}]`

func TestGenerate_RequestShape(t *testing.T) {
	c, api, _ := newTestClient(t, "", ok("tool_use", toolCall))

	if _, err := c.Generate(context.Background(), kbRequest()); err != nil {
		t.Fatal(err)
	}

	h := api.headers[0]
	if got := h.Get("anthropic-version"); got != "2026-10-21" {
		t.Errorf("anthropic-version = %q", got)
	}
	if got := h.Get("x-api-key"); got != "test-key" {
		t.Errorf("x-api-key = %q", got)
	}
	r := api.request(0)
	for _, removed := range []string{"temperature", "top_p", "top_k", "thinking"} {
		if _, ok := r.raw[removed]; ok {
			t.Errorf("request sends %q", removed)
		}
	}
	if r.Model != DefaultModel || r.MaxTokens != 16000 {
		t.Errorf("model/max_tokens = %s/%d", r.Model, r.MaxTokens)
	}
	if r.ToolChoice == nil || r.ToolChoice.Type != "auto" {
		t.Errorf("tool_choice = %+v, want auto", r.ToolChoice)
	}
	if r.OutputConfig == nil || r.OutputConfig.Effort != "medium" {
		t.Errorf("output_config = %+v, want effort medium", r.OutputConfig)
	}
	if len(r.Tools) != 2 || r.Tools[0].Type != "web_search_20260209" || r.Tools[0].MaxUses != 5 ||
		r.Tools[1].Name != "generate_kb_entry" || !r.Tools[1].Strict {
		t.Errorf("tools = %+v", r.Tools)
	}
	if string(r.Messages[0].Content) != `"finding <b>&</b>"` {
		t.Errorf("user content = %s, want it unescaped", r.Messages[0].Content)
	}
}

func TestGenerate_OlderModelGetsBasicSearchAndNoEffort(t *testing.T) {
	c, api, _ := newTestClient(t, "claude-sonnet-4-5", ok("tool_use", toolCall))

	if _, err := c.Generate(context.Background(), kbRequest()); err != nil {
		t.Fatal(err)
	}
	r := api.request(0)
	if r.OutputConfig != nil {
		t.Errorf("output_config = %+v, want none", r.OutputConfig)
	}
	if r.Tools[0].Type != "web_search_20250305" {
		t.Errorf("web search tool = %s", r.Tools[0].Type)
	}
}

func TestGenerate_WithoutWebSearchSendsOnlySchemaTool(t *testing.T) {
	c, api, _ := newTestClient(t, "", ok("tool_use", toolCall))
	req := kbRequest()
	req.WebSearch = false

	if _, err := c.Generate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if r := api.request(0); len(r.Tools) != 1 || r.Tools[0].Name != "generate_kb_entry" {
		t.Errorf("tools = %+v", r.Tools)
	}
}

func TestGenerate_ThinkingBeforeToolUseReturnsInput(t *testing.T) {
	c, _, _ := newTestClient(t, "", ok("tool_use", toolCall))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ai.OutcomeOK || string(res.JSON) != `{"business":{"title":"x"}}` {
		t.Errorf("result = %+v", res)
	}
	if res.Model != "claude-sonnet-5-5" || res.Usage.InputTokens != 100 || res.WebSearches != 1 {
		t.Errorf("model/usage = %s %+v %d", res.Model, res.Usage, res.WebSearches)
	}
}

func TestGenerate_PauseTurnEchoesContentByteForByte(t *testing.T) {
	// HTML characters, an escape sequence, a thinking signature and a block
	// type this client does not know must all go back as received.
	paused := `[{"type":"thinking","thinking":"","signature":"EqQBCkYIBxgCKkA+/="},` +
		`{"type":"server_tool_use","id":"srvtoolu_1","name":"web_search","input":{"query":"CVE <2024> & <x>"}},` +
		`{"type":"web_search_tool_result","tool_use_id":"srvtoolu_1","content":[{"type":"web_search_result","url":"https://a.example/?a=1&b=2","title":"<T>","encrypted_content":"Zm9v+/=="}]},` +
		`{"type":"future_block","data":{"nested":[1,2.50,true,null]}}]`
	c, api, _ := newTestClient(t, "", ok("pause_turn", paused), ok("tool_use", toolCall))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ai.OutcomeOK || res.WebSearches != 2 || res.Usage.InputTokens != 200 {
		t.Fatalf("result = %+v", res)
	}
	r := api.request(1)
	if len(r.Messages) != 2 || r.Messages[1].Role != "assistant" {
		t.Fatalf("continuation messages = %d, want user + assistant", len(r.Messages))
	}
	if got := string(r.Messages[1].Content); got != paused {
		t.Errorf("echoed content differs:\n got %s\nwant %s", got, paused)
	}
}

func TestGenerate_MaxTokensIsTruncatedWithoutReadingPartialToolCall(t *testing.T) {
	c, api, _ := newTestClient(t, "", ok("max_tokens", toolCall))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ai.OutcomeTruncated || res.JSON != nil {
		t.Errorf("result = %+v", res)
	}
	if api.calls() != 1 {
		t.Errorf("calls = %d", api.calls())
	}
}

func TestGenerate_RefusalIsFinalAndNotRetried(t *testing.T) {
	refused := reply{http.StatusOK, `{"model":"claude-sonnet-5-5","stop_reason":"refusal",` +
		`"stop_details":{"type":"refusal","category":"cyber","explanation":"x"},"content":[],` +
		`"usage":{"input_tokens":5,"output_tokens":0}}`}
	c, api, waits := newTestClient(t, "", refused)

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ai.OutcomeRefused || res.RefusalCategory != "cyber" {
		t.Errorf("result = %+v", res)
	}
	if api.calls() != 1 || len(*waits) != 0 {
		t.Errorf("calls = %d, backoffs = %v; a refusal must not be retried", api.calls(), *waits)
	}
}

func TestGenerate_RefusalWithNullDetails(t *testing.T) {
	c, _, _ := newTestClient(t, "", ok("refusal", `[]`))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil || res.Outcome != ai.OutcomeRefused || res.RefusalCategory != "" {
		t.Errorf("result = %+v, err = %v", res, err)
	}
}

func TestGenerate_NoToolCallRetriesOnceThenNoOutput(t *testing.T) {
	text := `[{"type":"text","text":"Here is the entry: {...}"}]`
	c, api, _ := newTestClient(t, "", ok("end_turn", text), ok("end_turn", text))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != ai.OutcomeNoOutput {
		t.Errorf("outcome = %s", res.Outcome)
	}
	if api.calls() != 2 {
		t.Fatalf("calls = %d, want 2", api.calls())
	}
	r := api.request(1)
	if len(r.Messages) != 3 || r.Messages[1].Role != "assistant" || string(r.Messages[1].Content) != text ||
		r.Messages[2].Role != "user" || !strings.Contains(string(r.Messages[2].Content), "generate_kb_entry") {
		t.Errorf("retry messages = %+v", r.Messages)
	}
}

func TestGenerate_NoToolCallThenToolCallSucceeds(t *testing.T) {
	c, _, _ := newTestClient(t, "", ok("end_turn", `[{"type":"text","text":"done"}]`), ok("tool_use", toolCall))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil || res.Outcome != ai.OutcomeOK {
		t.Errorf("result = %+v, err = %v", res, err)
	}
}

func TestGenerate_RetriesRateLimitAndOverload(t *testing.T) {
	c, api, waits := newTestClient(t, "",
		reply{429, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`},
		reply{529, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`},
		ok("tool_use", toolCall))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil || res.Outcome != ai.OutcomeOK {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	if api.calls() != 3 || len(*waits) != 2 || (*waits)[0] != 1 || (*waits)[1] != 2 {
		t.Errorf("calls = %d, backoff attempts = %v", api.calls(), *waits)
	}
}

func TestGenerate_BadRequestIsNotRetried(t *testing.T) {
	c, api, _ := newTestClient(t, "", reply{400, `{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`})

	_, err := c.Generate(context.Background(), kbRequest())
	if err == nil || !strings.Contains(err.Error(), "HTTP 400: bad") {
		t.Errorf("err = %v", err)
	}
	if api.calls() != 1 {
		t.Errorf("calls = %d", api.calls())
	}
}

func TestGenerate_TextWithoutSchema(t *testing.T) {
	c, api, _ := newTestClient(t, "",
		ok("end_turn", `[{"type":"thinking","thinking":"","signature":"s"},{"type":"text","text":" Two sentences. "}]`))

	res, err := c.Generate(context.Background(), ai.Request{System: "s", User: "u", MaxOutputTokens: 4096})
	if err != nil || res.Outcome != ai.OutcomeOK || res.Text != "Two sentences." {
		t.Errorf("result = %+v, err = %v", res, err)
	}
	if r := api.request(0); r.Tools != nil || r.ToolChoice != nil {
		t.Errorf("text request sends tools: %+v", r)
	}
}

func TestGenerate_ResponseTimeoutIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select { // longer than the client timeout below
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	c := New("test-key", "", srv.URL, zap.NewNop())
	c.httpClient.Timeout = 100 * time.Millisecond
	var waits int
	c.backoff = func(int) time.Duration { waits++; return time.Millisecond }

	_, err := c.Generate(context.Background(), kbRequest())
	if err == nil {
		t.Fatal("no error after the request timed out")
	}
	if n := calls.Load(); n != 1 || waits != 0 {
		t.Errorf("requests = %d, backoffs = %d; a timed-out generation must not be sent again", n, waits)
	}
}

func TestGenerate_ConnectionRefusedIsRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens: every dial is refused
	c := New("test-key", "", "http://"+addr, zap.NewNop())
	var waits int
	c.backoff = func(int) time.Duration { waits++; return time.Millisecond }

	if _, err := c.Generate(context.Background(), kbRequest()); err == nil || !strings.Contains(err.Error(), "max retries exceeded") {
		t.Fatalf("err = %v", err)
	}
	if waits != maxRetries {
		t.Errorf("backoffs = %d, want %d", waits, maxRetries)
	}
}

func TestGenerate_PauseTurnLimit(t *testing.T) {
	// One request plus five continuations; the literal 6 makes a change to
	// maxContinuations fail this test.
	var replies []reply
	for range 7 {
		replies = append(replies, ok("pause_turn", `[{"type":"server_tool_use","id":"s","name":"web_search","input":{}}]`))
	}
	c, api, _ := newTestClient(t, "", replies...)

	_, err := c.Generate(context.Background(), kbRequest())
	if err == nil || !strings.Contains(err.Error(), "still paused") {
		t.Fatalf("err = %v", err)
	}
	if api.calls() != 6 {
		t.Errorf("requests = %d, want 6", api.calls())
	}
}

func TestGenerate_SecondPauseExtendsTheSameAssistantTurn(t *testing.T) {
	first := `[{"type":"thinking","thinking":"","signature":"a"},{"type":"server_tool_use","id":"s1","name":"web_search","input":{"query":"<x>"}}]`
	second := `[{"type":"web_search_tool_result","tool_use_id":"s1","content":[]},{"type":"server_tool_use","id":"s2","name":"web_search","input":{}}]`
	withContainer := func(stop, content string) reply {
		r := ok(stop, content)
		r.body = strings.Replace(r.body, `"content":`, `"container":{"id":"container_1","expires_at":"2026-11-22T18:00:00Z"},"content":`, 1)
		return r
	}
	c, api, _ := newTestClient(t, "", withContainer("pause_turn", first), withContainer("pause_turn", second), ok("tool_use", toolCall))

	res, err := c.Generate(context.Background(), kbRequest())
	if err != nil || res.Outcome != ai.OutcomeOK {
		t.Fatalf("result = %+v, err = %v", res, err)
	}
	r := api.request(2)
	if len(r.Messages) != 2 || r.Messages[0].Role != "user" || r.Messages[1].Role != "assistant" {
		t.Fatalf("messages = %d, want user + one assistant turn", len(r.Messages))
	}
	want := "[" + first[1:len(first)-1] + "," + second[1:len(second)-1] + "]"
	if got := string(r.Messages[1].Content); got != want {
		t.Errorf("assistant turn:\n got %s\nwant %s", got, want)
	}
	if got := string(r.raw["container"]); got != `"container_1"` {
		t.Errorf("container = %s, want the paused turn's container", got)
	}
	if _, ok := api.request(0).raw["container"]; ok {
		t.Error("first request sends a container")
	}
}

func TestGenerate_DoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
	}))
	t.Cleanup(other.Close)
	c, api, _ := newTestClient(t, "", reply{http.StatusTemporaryRedirect, ""})
	// The fake API answers 307 with this Location.
	api.location = other.URL + "/v1/messages"

	_, err := c.Generate(context.Background(), kbRequest())
	if err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("err = %v", err)
	}
	if leaked.Load() != 0 || api.calls() != 1 {
		t.Errorf("redirect followed: other host got %d requests", leaked.Load())
	}
}
