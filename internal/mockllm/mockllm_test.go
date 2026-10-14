/**
 * Copyright 2026 the original author or authors from the Chautari project.
 *
 * This file is part of the Chautari project, see https://github.com/lukelittle/chautari
 * for more information.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package mockllm

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(New(opts))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url, body string, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func chatBody(model, prompt string, extra string) string {
	p, _ := json.Marshal(prompt)
	return `{"model":"` + model + `","messages":[{"role":"system","content":"You are helpful."},{"role":"user","content":` + string(p) + `}]` + extra + `}`
}

func decodeCompletion(t *testing.T, b []byte) chatCompletion {
	t.Helper()
	var c chatCompletion
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return c
}

func expectOpenAIError(t *testing.T, resp *http.Response, b []byte, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, status, b)
	}
	var e struct {
		Error struct {
			Message, Type, Code string
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("decode error body %s: %v", b, err)
	}
	if e.Error.Code != code || e.Error.Message == "" || e.Error.Type == "" {
		t.Fatalf("error = %+v, want code %q", e.Error, code)
	}
}

func TestEstimateTokens(t *testing.T) {
	for s, want := range map[string]int{"": 1, "a": 1, "abcd": 1, "abcde": 2, "12345678": 2, "héllo": 2} {
		if got := EstimateTokens(s); got != want {
			t.Errorf("EstimateTokens(%q) = %d, want %d", s, got, want)
		}
	}
}

func TestHealthz(t *testing.T) {
	srv := newServer(t, Options{})
	resp, b := do(t, "GET", srv.URL+"/healthz", "", nil)
	if resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("healthz = %d %q", resp.StatusCode, b)
	}
}

func TestModels(t *testing.T) {
	srv := newServer(t, Options{})
	resp, b := do(t, "GET", srv.URL+"/v1/models", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var list struct {
		Object string
		Data   []struct{ ID, Object string }
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	if list.Object != "list" || len(list.Data) != len(Models) {
		t.Fatalf("list = %+v", list)
	}
	for i, m := range list.Data {
		if m.ID != Models[i] || m.Object != "model" {
			t.Errorf("model %d = %+v", i, m)
		}
	}
}

func TestChatCompletion(t *testing.T) {
	srv := newServer(t, Options{})
	prompt := "What is the status of the overnight batch?"
	body := chatBody("any-model-at-all", prompt, "")
	resp, b := do(t, "POST", srv.URL+"/v1/chat/completions", body, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	c := decodeCompletion(t, b)
	reply := Reply(prompt)
	if c.Object != "chat.completion" || c.Model != "any-model-at-all" || !strings.HasPrefix(c.ID, "chatcmpl-mock-") {
		t.Fatalf("envelope = %+v", c)
	}
	if c.Created != DefaultCreated {
		t.Errorf("created = %d", c.Created)
	}
	if len(c.Choices) != 1 || c.Choices[0].Message.Content != reply || c.Choices[0].Message.Role != "assistant" || c.Choices[0].FinishReason != "stop" {
		t.Fatalf("choices = %+v", c.Choices)
	}
	want := Usage{
		PromptTokens:     EstimateTokens("You are helpful." + prompt),
		CompletionTokens: EstimateTokens(reply),
	}
	want.TotalTokens = want.PromptTokens + want.CompletionTokens
	if c.Usage != want {
		t.Fatalf("usage = %+v, want %+v", c.Usage, want)
	}

	_, b2 := do(t, "POST", srv.URL+"/v1/chat/completions", body, nil)
	if string(b) != string(b2) {
		t.Fatalf("not deterministic:\n%s\n%s", b, b2)
	}
	_, b3 := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("any-model-at-all", prompt+"?", ""), nil)
	if decodeCompletion(t, b3).ID == c.ID {
		t.Error("different prompts share an id")
	}
}

func TestRepliesVary(t *testing.T) {
	seen := map[string]bool{}
	for i := range 50 {
		seen[Reply(strings.Repeat("x", i))] = true
	}
	if len(seen) < 4 {
		t.Fatalf("only %d distinct replies", len(seen))
	}
}

func TestNowOption(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	srv := newServer(t, Options{Now: func() time.Time { return now }})
	_, b := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "hi", ""), nil)
	if got := decodeCompletion(t, b).Created; got != now.Unix() {
		t.Fatalf("created = %d", got)
	}
}

func TestContentParts(t *testing.T) {
	srv := newServer(t, Options{})
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":"Hello "},{"type":"image_url","image_url":{"url":"x"}},{"type":"text","text":"there"}]}]}`
	resp, b := do(t, "POST", srv.URL+"/v1/chat/completions", body, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	c := decodeCompletion(t, b)
	if c.Choices[0].Message.Content != Reply("Hello there") {
		t.Fatalf("reply = %q", c.Choices[0].Message.Content)
	}
	if c.Usage.PromptTokens != EstimateTokens("Hello there") {
		t.Fatalf("prompt tokens = %d", c.Usage.PromptTokens)
	}
}

// readSSE returns the data payloads of an SSE body in order.
func readSSE(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	for sc.Scan() {
		if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			out = append(out, d)
		}
	}
	return out
}

func TestStreaming(t *testing.T) {
	srv := newServer(t, Options{})
	prompt := "Summarise the loan pipeline"
	_, plain := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("claude-sonnet-4-5", prompt, ""), nil)
	want := decodeCompletion(t, plain)

	for _, includeUsage := range []bool{true, false} {
		extra := `,"stream":true`
		if includeUsage {
			extra += `,"stream_options":{"include_usage":true}`
		}
		resp, b := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("claude-sonnet-4-5", prompt, extra), nil)
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("content-type %q", ct)
		}
		events := readSSE(t, b)
		if events[len(events)-1] != "[DONE]" {
			t.Fatalf("last event %q", events[len(events)-1])
		}
		var text strings.Builder
		var usage *Usage
		contentChunks := 0
		for _, ev := range events[:len(events)-1] {
			var ch chatChunk
			if err := json.Unmarshal([]byte(ev), &ch); err != nil {
				t.Fatalf("chunk %q: %v", ev, err)
			}
			if ch.Object != "chat.completion.chunk" || ch.ID != want.ID || ch.Model != "claude-sonnet-4-5" {
				t.Fatalf("chunk envelope %+v", ch)
			}
			if ch.Usage != nil {
				if len(ch.Choices) != 0 {
					t.Fatalf("usage chunk has choices: %s", ev)
				}
				usage = ch.Usage
				continue
			}
			if c := ch.Choices[0].Delta.Content; c != "" {
				contentChunks++
				text.WriteString(c)
			}
		}
		if text.String() != want.Choices[0].Message.Content {
			t.Fatalf("stream text %q != %q", text.String(), want.Choices[0].Message.Content)
		}
		if contentChunks < 2 {
			t.Errorf("only %d content chunks", contentChunks)
		}
		if includeUsage && (usage == nil || *usage != want.Usage) {
			t.Fatalf("usage chunk = %+v, want %+v", usage, want.Usage)
		}
		if !includeUsage && usage != nil {
			t.Fatal("usage chunk sent without include_usage")
		}
		if includeUsage {
			if !strings.Contains(events[len(events)-2], `"choices":[]`) {
				t.Errorf("usage chunk not second-to-last: %s", events[len(events)-2])
			}
		}
	}
}

func TestSplitChunks(t *testing.T) {
	for _, s := range []string{"", "one", "a b c d e f g", "  lead\n\ntrail  ", longReply()} {
		if got := strings.Join(splitChunks(s, 3), ""); got != s {
			t.Errorf("splitChunks(%q) rejoined = %q", s, got)
		}
	}
}

func TestLeakMarkers(t *testing.T) {
	srv := newServer(t, Options{})
	cases := map[string]string{
		MarkerLeakSSN:   "The customer's SSN is 123-45-6789.",
		MarkerLeakCard:  "Card on file: 4111 1111 1111 1111.",
		MarkerLeakEmail: "Contact jane.doe@example.com.",
	}
	for marker, want := range cases {
		_, b := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "Tell me about the customer "+marker, ""), nil)
		if got := decodeCompletion(t, b).Choices[0].Message.Content; !strings.Contains(got, want) {
			t.Errorf("%s: reply %q lacks %q", marker, got, want)
		}
	}
	all := Reply(MarkerLeakSSN + MarkerLeakCard + MarkerLeakEmail)
	for _, want := range cases {
		if !strings.Contains(all, want) {
			t.Errorf("combined reply lacks %q", want)
		}
	}
	if strings.Contains(Reply("plain question"), "SSN") {
		t.Error("leak without marker")
	}
}

func TestErrorMarker(t *testing.T) {
	srv := newServer(t, Options{})
	resp, b := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "please [[error]]", ""), nil)
	expectOpenAIError(t, resp, b, http.StatusInternalServerError, "mock_error")
}

func TestLongMarker(t *testing.T) {
	srv := newServer(t, Options{})
	_, b := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "report [[long]]", ""), nil)
	c := decodeCompletion(t, b)
	words := len(strings.Fields(c.Choices[0].Message.Content))
	if words < 1800 || words > 2500 {
		t.Fatalf("long reply has %d words", words)
	}
	if c.Usage.CompletionTokens < 2000 {
		t.Fatalf("completion tokens = %d", c.Usage.CompletionTokens)
	}
}

func TestSlowMarker(t *testing.T) {
	srv := newServer(t, Options{SlowDelay: 150 * time.Millisecond})
	start := time.Now()
	resp, _ := do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "[[slow]] hi", ""), nil)
	if resp.StatusCode != 200 || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("status %d after %v", resp.StatusCode, time.Since(start))
	}
}

func TestSlowMarkerHonoursCancellation(t *testing.T) {
	h := New(Options{SlowDelay: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, "POST", "/v1/chat/completions", strings.NewReader(chatBody("gpt-4o", "[[slow]]", "")))
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler ignored context cancellation")
	}
}

func TestDefaultSlowDelay(t *testing.T) {
	if DefaultSlowDelay != 2*time.Second {
		t.Fatal("default slow delay changed")
	}
}

func TestAuth(t *testing.T) {
	srv := newServer(t, Options{APIKey: "sekret"})
	resp, b := do(t, "GET", srv.URL+"/v1/models", "", nil)
	expectOpenAIError(t, resp, b, http.StatusUnauthorized, "invalid_api_key")
	resp, b = do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "hi", ""), map[string]string{"Authorization": "Bearer wrong"})
	expectOpenAIError(t, resp, b, http.StatusUnauthorized, "invalid_api_key")
	resp, _ = do(t, "POST", srv.URL+"/v1/chat/completions", chatBody("gpt-4o", "hi", ""), map[string]string{"Authorization": "Bearer sekret"})
	if resp.StatusCode != 200 {
		t.Fatalf("authorised status %d", resp.StatusCode)
	}
	if resp, _ := do(t, "GET", srv.URL+"/healthz", "", nil); resp.StatusCode != 200 {
		t.Fatal("healthz should not require auth")
	}
}

func TestBadRequests(t *testing.T) {
	srv := newServer(t, Options{})
	cases := []struct{ body, code string }{
		{`{not json`, "invalid_json"},
		{`{"model":"gpt-4o"}`, "missing_messages"},
		{`{"model":"gpt-4o","messages":[]}`, "missing_messages"},
		{`{"messages":[{"role":"user","content":"hi"}]}`, "missing_model"},
		{`{"model":"gpt-4o","messages":[{"role":"user","content":42}]}`, "invalid_content"},
	}
	for _, tc := range cases {
		resp, b := do(t, "POST", srv.URL+"/v1/chat/completions", tc.body, nil)
		expectOpenAIError(t, resp, b, http.StatusBadRequest, tc.code)
	}
	resp, b := do(t, "GET", srv.URL+"/v1/nope", "", nil)
	expectOpenAIError(t, resp, b, http.StatusNotFound, "unknown_url")
	resp, b = do(t, "GET", srv.URL+"/v1/chat/completions", "", nil)
	expectOpenAIError(t, resp, b, http.StatusMethodNotAllowed, "method_not_allowed")
}

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func rpc(t *testing.T, url, body string) (*http.Response, rpcReply) {
	t.Helper()
	resp, b := do(t, "POST", url, body, nil)
	var r rpcReply
	if len(b) > 0 {
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("decode %s: %v", b, err)
		}
	}
	return resp, r
}

func TestMCPInitialize(t *testing.T) {
	srv := newServer(t, Options{})
	resp, r := rpc(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	if resp.Header.Get("Mcp-Session-Id") == "" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v", resp.Header)
	}
	var res struct {
		ProtocolVersion string
		Capabilities    map[string]json.RawMessage
		ServerInfo      struct{ Name, Version string }
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.ProtocolVersion != "2025-03-26" || res.ServerInfo.Name != MCPServerName || res.ServerInfo.Version != "0.1.0" || res.Capabilities["tools"] == nil {
		t.Fatalf("result %+v", res)
	}
	if string(r.ID) != "1" {
		t.Fatalf("id %s", r.ID)
	}

	_, r = rpc(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","id":"a","method":"initialize","params":{}}`)
	if !strings.Contains(string(r.Result), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("default version: %s", r.Result)
	}

	resp, _ = rpc(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification status %d", resp.StatusCode)
	}
	_, r = rpc(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if r.Error != nil || string(r.Result) != "{}" {
		t.Fatalf("ping %+v", r)
	}
	resp, _ = do(t, "GET", srv.URL+"/mcp", "", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp = %d", resp.StatusCode)
	}
}

func TestMCPToolsList(t *testing.T) {
	srv := newServer(t, Options{})
	_, r := rpc(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	var res struct {
		Tools []struct {
			Name        string
			Description string
			InputSchema struct {
				Type       string
				Properties map[string]map[string]any
				Required   []string
			}
		}
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != len(MCPTools) {
		t.Fatalf("tools %+v", res.Tools)
	}
	required := map[string][]string{"search_issues": {"query"}, "get_issue": {"key"}, "update_loan": {"loan_id", "status"}}
	for i, tool := range res.Tools {
		if tool.Name != MCPTools[i] || tool.Description == "" || tool.InputSchema.Type != "object" {
			t.Fatalf("tool %+v", tool)
		}
		if strings.Join(tool.InputSchema.Required, ",") != strings.Join(required[tool.Name], ",") {
			t.Errorf("%s required = %v", tool.Name, tool.InputSchema.Required)
		}
		for _, p := range tool.InputSchema.Required {
			if tool.InputSchema.Properties[p]["type"] != "string" {
				t.Errorf("%s.%s schema %v", tool.Name, p, tool.InputSchema.Properties[p])
			}
		}
	}
}

func callToolText(t *testing.T, url, name, args string) (string, bool, *rpcError) {
	t.Helper()
	_, r := rpc(t, url+"/mcp", `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`)
	if r.Error != nil {
		return "", false, r.Error
	}
	var res toolResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		t.Fatalf("content %+v", res.Content)
	}
	return res.Content[0].Text, res.IsError, nil
}

func TestMCPToolsCall(t *testing.T) {
	srv := newServer(t, Options{})
	text, isErr, e := callToolText(t, srv.URL, "search_issues", `{"query":"payments"}`)
	if e != nil || isErr || !strings.Contains(text, "OPS-311") {
		t.Fatalf("search_issues: %q %v %v", text, isErr, e)
	}
	text, _, _ = callToolText(t, srv.URL, "search_issues", `{"query":"zzz"}`)
	if !strings.Contains(text, "No issues") {
		t.Fatalf("empty search: %q", text)
	}
	text, isErr, e = callToolText(t, srv.URL, "get_issue", `{"key":"LOAN-101"}`)
	if e != nil || isErr || !strings.Contains(text, "Income verification") {
		t.Fatalf("get_issue: %q", text)
	}
	a, _, _ := callToolText(t, srv.URL, "get_issue", `{"key":"XYZ-9"}`)
	b, _, _ := callToolText(t, srv.URL, "get_issue", `{"key":"XYZ-9"}`)
	if a != b || !strings.Contains(a, "XYZ-9") {
		t.Fatalf("synthetic issue not deterministic: %q %q", a, b)
	}
	text, isErr, e = callToolText(t, srv.URL, "update_loan", `{"loan_id":"L-1","status":"approved"}`)
	if e != nil || isErr || !strings.Contains(text, "Loan L-1 status updated to approved") {
		t.Fatalf("update_loan: %q", text)
	}
	_, isErr, e = callToolText(t, srv.URL, "update_loan", `{"loan_id":"L-1","status":"bogus"}`)
	if e != nil || !isErr {
		t.Fatalf("invalid status should be a tool error, got isError=%v err=%v", isErr, e)
	}
	_, _, e = callToolText(t, srv.URL, "update_loan", `{"loan_id":"L-1"}`)
	if e == nil || e.Code != -32602 {
		t.Fatalf("missing arg err = %v", e)
	}
	_, _, e = callToolText(t, srv.URL, "drop_tables", `{}`)
	if e == nil || e.Code != -32602 {
		t.Fatalf("unknown tool err = %v", e)
	}
}

func TestMCPErrors(t *testing.T) {
	srv := newServer(t, Options{})
	_, r := rpc(t, srv.URL+"/mcp", `{"jsonrpc":"2.0","id":4,"method":"resources/list"}`)
	if r.Error == nil || r.Error.Code != -32601 || string(r.ID) != "4" {
		t.Fatalf("unknown method %+v", r)
	}
	_, r = rpc(t, srv.URL+"/mcp", `{nope`)
	if r.Error == nil || r.Error.Code != -32700 || string(r.ID) != "null" {
		t.Fatalf("parse error %+v", r)
	}
	_, r = rpc(t, srv.URL+"/mcp", `{"id":1,"method":"ping"}`)
	if r.Error == nil || r.Error.Code != -32600 {
		t.Fatalf("invalid request %+v", r)
	}
}

func TestAgentCard(t *testing.T) {
	srv := newServer(t, Options{})
	for _, path := range []string{"/.well-known/agent-card.json", "/.well-known/agent.json"} {
		resp, b := do(t, "GET", srv.URL+path, "", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s status %d", path, resp.StatusCode)
		}
		var card struct {
			Name, Description, URL, Version, ProtocolVersion string
			Capabilities                                     struct{ Streaming bool }
			DefaultInputModes, DefaultOutputModes            []string
			Skills                                           []struct {
				ID, Name, Description string
				Tags                  []string
			}
		}
		if err := json.Unmarshal(b, &card); err != nil {
			t.Fatal(err)
		}
		if card.Name != "underwriting-agent" || card.URL != srv.URL+"/" || card.Version != "0.1.0" ||
			card.ProtocolVersion != "0.3.0" || card.Description == "" || card.Capabilities.Streaming {
			t.Fatalf("card %+v", card)
		}
		if len(card.DefaultInputModes) != 1 || card.DefaultInputModes[0] != "text/plain" || len(card.DefaultOutputModes) != 1 {
			t.Fatalf("modes %+v", card)
		}
		if len(card.Skills) != 1 || card.Skills[0].ID != "credit-memo" || card.Skills[0].Name != "Draft credit memo" || len(card.Skills[0].Tags) == 0 {
			t.Fatalf("skills %+v", card.Skills)
		}
	}
}

func TestA2AMessageSend(t *testing.T) {
	srv := newServer(t, Options{})
	body := `{"jsonrpc":"2.0","id":"r1","method":"message/send","params":{"message":{"kind":"message","role":"user","messageId":"m1","contextId":"c1","parts":[{"kind":"text","text":"Application 88231"}]}}}`
	_, r := rpc(t, srv.URL+"/", body)
	if r.Error != nil {
		t.Fatalf("error %+v", r.Error)
	}
	var msg a2aMessage
	if err := json.Unmarshal(r.Result, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Kind != "message" || msg.Role != "agent" || !strings.HasPrefix(msg.MessageID, "msg-mock-") || msg.ContextID != "c1" {
		t.Fatalf("msg %+v", msg)
	}
	if len(msg.Parts) != 1 || msg.Parts[0].Kind != "text" || !strings.HasPrefix(msg.Parts[0].Text, "Credit memo draft: ") {
		t.Fatalf("parts %+v", msg.Parts)
	}
	_, r2 := rpc(t, srv.URL+"/", body)
	if string(r2.Result) != string(r.Result) {
		t.Fatal("message/send not deterministic")
	}
	_, r = rpc(t, srv.URL+"/", `{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{}}`)
	if r.Error == nil || r.Error.Code != -32601 {
		t.Fatalf("unknown method %+v", r)
	}
	_, r = rpc(t, srv.URL+"/", `{"jsonrpc":"2.0","id":3,"method":"message/send","params":{}}`)
	if r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("missing message %+v", r)
	}
}
