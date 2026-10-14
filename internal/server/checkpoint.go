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

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/budget"
	"github.com/lukelittle/chautari/internal/dataplane"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/guardrails"
	"github.com/lukelittle/chautari/internal/policy"
)

// maxBody bounds request bodies, and buffered upstream responses.
const maxBody = 8 << 20

// HeaderDataClass lets a caller declare the sensitivity of a request. It can
// only raise the class above the app's default, never lower it.
const HeaderDataClass = "X-Chautari-Data-Class"

// defaultCompletionEstimate is the completion size reserved against budgets
// when a request sets no max_tokens.
const defaultCompletionEstimate = 1024

// auditTimeout bounds an audit write. Audit writes never use the request's
// context: a client hanging up must not erase the evidence of what it did.
const auditTimeout = 5 * time.Second

func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return "req_" + hex.EncodeToString(b)
}

// apiError writes an OpenAI-shaped error so existing SDKs surface it cleanly.
func apiError(w http.ResponseWriter, status int, typ, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{ //nolint:errcheck
		"message": msg, "type": typ, "code": code, "param": nil,
	}})
}

// authError answers a failed authentication without leaking internals.
func (s *Server) authError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUnauthorized) {
		apiError(w, http.StatusUnauthorized, "authentication_error", "invalid_api_key", "Chautari: missing or invalid API key")
		return
	}
	s.log.Error("authentication failed", "err", err)
	apiError(w, http.StatusInternalServerError, "server_error", "auth_failed", "Chautari: authentication is unavailable")
}

// writeAudit appends a record on a context detached from the request.
func (s *Server) writeAudit(ctx context.Context, rec audit.Record) error {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	_, err := s.audit.Write(actx, rec)
	if err != nil {
		s.log.Error("audit write failed", "err", err, "kind", rec.Kind, "resource", rec.Resource)
	}
	return err
}

// mustAudit writes a record and, if it cannot, answers 503 and returns false:
// Chautari does not act without leaving evidence.
func (s *Server) mustAudit(w http.ResponseWriter, ctx context.Context, rec audit.Record) bool {
	if err := s.writeAudit(ctx, rec); err != nil {
		http.Error(w, "Chautari: the audit log is unavailable, so the request was refused", http.StatusServiceUnavailable)
		return false
	}
	return true
}

// dataClass is the effective sensitivity of a request: the highest of the
// caller's declaration, the app's default and the estate's default. A caller
// may raise it but never lower it. An unknown declaration is passed through
// so that policy refuses it by name.
func (s *Server) dataClass(r *http.Request, c caller, rt *runtime) string {
	declared := estate.DataClass(strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderDataClass))))
	if declared != "" && !declared.Valid() {
		return string(declared)
	}
	best := rt.estate.DefaultDataClass
	for _, dc := range []estate.DataClass{c.app.DataClass, declared} {
		if dc.Valid() && dc.Rank() > best.Rank() {
			best = dc
		}
	}
	return string(best)
}

// promptDigest is an HMAC of the (redacted) prompt: stable enough to match
// an incident to a record, useless for brute-forcing short PII out of the log.
func (s *Server) promptDigest(texts []string) string {
	m := hmac.New(sha256.New, s.digestKey)
	for _, t := range texts {
		m.Write([]byte(t))
		m.Write([]byte{0})
	}
	return hex.EncodeToString(m.Sum(nil))
}

// estimateTokens approximates tokens as characters / 4, the same rule of
// thumb providers document. It is only used before usage is known.
func estimateTokens(s string) int64 {
	n := int64(math.Ceil(float64(len([]rune(s))) / 4))
	if n < 1 {
		n = 1
	}
	return n
}

// textRef points at one string inside a request or response so guardrails
// can read it and rewrite it in place.
type textRef struct {
	get func() string
	set func(string)
}

func refAt(m map[string]any, key string) (textRef, bool) {
	if _, ok := m[key].(string); !ok {
		return textRef{}, false
	}
	return textRef{func() string { return m[key].(string) }, func(v string) { m[key] = v }}, true
}

// messageTexts collects every string a provider reads from, or a client
// receives in, chat messages: content (string or text parts), refusals, and
// tool and function call arguments. Anything a model can be told, or can say,
// passes the guardrails.
func messageTexts(messages []any) []textRef {
	var refs []textRef
	add := func(m map[string]any, key string) {
		if r, ok := refAt(m, key); ok {
			refs = append(refs, r)
		}
	}
	for _, x := range messages {
		msg, ok := x.(map[string]any)
		if !ok {
			continue
		}
		add(msg, "content")
		add(msg, "refusal")
		if parts, ok := msg["content"].([]any); ok {
			for _, p := range parts {
				if part, ok := p.(map[string]any); ok {
					add(part, "text")
					add(part, "refusal")
				}
			}
		}
		if calls, ok := msg["tool_calls"].([]any); ok {
			for _, tc := range calls {
				if call, ok := tc.(map[string]any); ok {
					if fn, ok := call["function"].(map[string]any); ok {
						add(fn, "arguments")
					}
				}
			}
		}
		if fn, ok := msg["function_call"].(map[string]any); ok {
			add(fn, "arguments")
		}
	}
	return refs
}

// requestTexts adds tool and function definitions, whose descriptions are
// instructions to the model, to the message texts.
func requestTexts(body map[string]any) []textRef {
	messages, _ := body["messages"].([]any)
	refs := messageTexts(messages)
	if tools, ok := body["tools"].([]any); ok {
		for _, t := range tools {
			if tool, ok := t.(map[string]any); ok {
				if fn, ok := tool["function"].(map[string]any); ok {
					if r, ok := refAt(fn, "description"); ok {
						refs = append(refs, r)
					}
				}
			}
		}
	}
	if fns, ok := body["functions"].([]any); ok {
		for _, f := range fns {
			if fn, ok := f.(map[string]any); ok {
				if r, ok := refAt(fn, "description"); ok {
					refs = append(refs, r)
				}
			}
		}
	}
	return refs
}

func readTexts(refs []textRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.get()
	}
	return out
}

// requestRecord accumulates what the audit record for one call will say.
type requestRecord struct {
	id         string
	start      time.Time
	c          caller
	model      estate.Model
	dataClass  string
	stream     bool
	digest     string
	findings   []guardrails.Finding
	decision   string
	reasons    []string
	status     int
	usage      usage
	estimated  bool // usage was estimated because the provider's figure never arrived
	cost       float64
	disconnect bool
}

type usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

func (rec *requestRecord) auditRecord(resource string) audit.Record {
	details := map[string]any{
		"request_id":    rec.id,
		"app":           rec.c.app.Name,
		"data_class":    rec.dataClass,
		"stream":        rec.stream,
		"status":        rec.status,
		"latency_ms":    time.Since(rec.start).Milliseconds(),
		"prompt_digest": rec.digest,
	}
	if rec.usage.TotalTokens > 0 {
		details["prompt_tokens"] = rec.usage.PromptTokens
		details["completion_tokens"] = rec.usage.CompletionTokens
		details["cost_usd"] = math.Round(rec.cost*1e8) / 1e8
	}
	if rec.estimated {
		details["usage_estimated"] = true
	}
	if rec.disconnect {
		details["client_disconnected"] = true
	}
	if len(rec.findings) > 0 {
		fs := make([]map[string]any, len(rec.findings))
		for i, f := range rec.findings {
			fs[i] = map[string]any{"policy": f.Policy, "detector": f.Detector, "action": string(f.Action), "count": f.Count}
		}
		details["findings"] = fs
	}
	return audit.Record{
		Kind: audit.KindRequest, Actor: rec.c.key.ID, Subject: rec.c.team.Name + "/" + rec.c.app.Name,
		Action: policy.ActionModel, Resource: resource, Decision: rec.decision, Reasons: rec.reasons, Details: details,
	}
}

// strongestDecision folds guardrail findings into the audit decision.
func strongestDecision(findings []guardrails.Finding) string {
	var best estate.Action
	for _, f := range findings {
		if f.Action.Strength() > best.Strength() {
			best = f.Action
		}
	}
	switch best {
	case estate.Redact:
		return audit.Redact
	case estate.Flag:
		return audit.Flag
	case estate.Block:
		return audit.Block
	}
	return audit.Allow
}

// reply is a complete response held back until its audit record is safely
// written: if the evidence cannot be recorded, the client gets a 503 instead.
type reply struct {
	status  int
	header  http.Header
	body    []byte
	errType string
	errCode string
	errMsg  string
}

func errorReply(status int, typ, code, msg string) *reply {
	return &reply{status: status, errType: typ, errCode: code, errMsg: msg}
}

func (rp *reply) write(w http.ResponseWriter) {
	if rp.errCode != "" {
		apiError(w, rp.status, rp.errType, rp.errCode, rp.errMsg)
		return
	}
	for k, v := range rp.header {
		w.Header()[k] = v
	}
	w.WriteHeader(rp.status)
	w.Write(rp.body)
}

// conclude writes the audit record for a request and then its reply. If the
// record cannot be written, the reply is withheld.
func (s *Server) conclude(w http.ResponseWriter, ctx context.Context, rec *requestRecord, resource string, rp *reply) {
	if rec.decision == "" {
		rec.decision = strongestDecision(rec.findings)
	}
	w.Header().Set("X-Chautari-Decision", rec.decision)
	if err := s.writeAudit(ctx, rec.auditRecord(resource)); err != nil {
		apiError(w, http.StatusServiceUnavailable, "server_error", "audit_unavailable", "Chautari: the audit log is unavailable, so the response was withheld")
		return
	}
	if rp != nil {
		rp.write(w)
	}
}

func (s *Server) chatCompletions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt := s.runtime()
	rec := &requestRecord{id: newRequestID(), start: time.Now()}
	w.Header().Set("X-Chautari-Request-Id", rec.id)

	c, err := s.authenticate(ctx, r, rt)
	if err != nil {
		s.authError(w, err)
		return
	}
	rec.c = c

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		apiError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "body_too_large", "Chautari: request body too large or unreadable")
		return
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "invalid_json", "Chautari: request body is not a JSON object")
		return
	}
	modelName, _ := body["model"].(string)
	messages, _ := body["messages"].([]any)
	if modelName == "" || len(messages) == 0 {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "missing_fields", "Chautari: model and messages are required")
		return
	}
	rec.stream, _ = body["stream"].(bool)
	rec.dataClass = s.dataClass(r, c, rt)
	texts := requestTexts(body)
	resource := "model/" + modelName

	// 1. Policy.
	d := s.policy.Decide(ctx, policy.Input{
		Subject:   policy.Subject{Team: c.team.Name, App: c.app.Name, Key: c.key.ID},
		Action:    policy.ActionModel,
		Resource:  policy.Resource{Name: modelName},
		DataClass: rec.dataClass,
	})
	if !d.Allow {
		rec.digest = s.promptDigest(readTexts(texts))
		rec.decision, rec.reasons, rec.status = audit.Deny, d.Reasons, http.StatusForbidden
		s.conclude(w, ctx, rec, resource, errorReply(http.StatusForbidden, "permission_error", "policy_denied", "Chautari policy: "+strings.Join(d.Reasons, "; ")))
		return
	}
	rec.model, _ = rt.estate.Model(modelName)

	// 2. Budgets and rate limits, reserving the estimated cost.
	estPrompt := estimateTokens(strings.Join(readTexts(texts), "\n"))
	estCompletion := int64(defaultCompletionEstimate)
	for _, k := range []string{"max_completion_tokens", "max_tokens"} {
		if v, ok := body[k].(float64); ok && v > 0 {
			estCompletion = int64(v)
			break
		}
	}
	subject := budget.Subject{Team: c.team.Name, App: c.app.Name, Key: c.key.ID}
	res, err := s.limiter.Check(ctx, rt.estate, subject, estPrompt, rec.model.Cost(estPrompt, estCompletion))
	if err != nil {
		rec.digest = s.promptDigest(readTexts(texts))
		rec.reasons = []string{err.Error()}
		var ex *budget.Exceeded
		if errors.As(err, &ex) {
			rec.decision, rec.status = audit.Limit, http.StatusTooManyRequests
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(ex.RetryAfter.Seconds()))))
			code := "rate_limited"
			if ex.Kind == "budget" {
				code = "budget_exceeded"
			}
			s.conclude(w, ctx, rec, resource, errorReply(http.StatusTooManyRequests, "rate_limit_error", code, "Chautari: "+err.Error()))
			return
		}
		rec.decision, rec.status = audit.Error, http.StatusServiceUnavailable
		s.conclude(w, ctx, rec, resource, errorReply(http.StatusServiceUnavailable, "server_error", "budget_unavailable", "Chautari: budgets are unavailable, so the request was refused"))
		return
	}
	charged := false
	defer func() {
		if !charged {
			s.limiter.Release(res)
		}
	}()

	// 3. Inbound guardrails.
	in, err := rt.guardrails.Inspect(ctx, c.team.Name, estate.Inbound, readTexts(texts))
	if err == nil && in.Blocked {
		err = errors.New(in.Reason)
	}
	rec.findings = append(rec.findings, in.Findings...)
	if err != nil {
		rec.digest = s.promptDigest(readTexts(texts))
		rec.decision, rec.reasons, rec.status = audit.Block, []string{err.Error()}, http.StatusBadRequest
		s.conclude(w, ctx, rec, resource, errorReply(http.StatusBadRequest, "invalid_request_error", "guardrail_blocked", "Chautari guardrail: "+err.Error()))
		return
	}
	for i, t := range in.Texts {
		texts[i].set(t)
	}
	rec.digest = s.promptDigest(in.Texts)

	// 4. Forward. The upstream call is detached from the client: if the
	// client hangs up, the provider still charges us, so we still read the
	// usage and bill it.
	outbound := rt.guardrails.HasDirection(c.team.Name, estate.Outbound)
	if rec.stream {
		opts, _ := body["stream_options"].(map[string]any)
		if opts == nil {
			opts = map[string]any{}
		}
		opts["include_usage"] = true
		body["stream_options"] = opts
	}
	fwd, _ := json.Marshal(body)
	upctx := context.WithoutCancel(ctx)
	resp, err := s.cfg.Adapter.ChatCompletions(upctx, fwd, dataplane.Meta{Team: c.team.Name, App: c.app.Name, Model: modelName, RequestID: rec.id})
	if err != nil {
		s.log.Warn("data plane unreachable", "err", err, "request_id", rec.id)
		rec.decision, rec.reasons, rec.status = audit.Error, []string{"data plane unreachable"}, http.StatusBadGateway
		s.conclude(w, ctx, rec, resource, errorReply(http.StatusBadGateway, "server_error", "dataplane_unavailable", "Chautari: data plane unreachable"))
		return
	}
	defer resp.Body.Close()

	var rp *reply
	switch {
	case resp.StatusCode >= 400:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		rec.decision, rec.status = audit.Error, resp.StatusCode
		rec.reasons = []string{fmt.Sprintf("upstream returned %d", resp.StatusCode)}
		rp = &reply{status: resp.StatusCode, header: http.Header{"Content-Type": {resp.Header.Get("Content-Type")}}, body: b}
	case rec.stream && !outbound:
		s.streamThrough(w, resp, rec)
	case rec.stream:
		rp = s.streamBuffered(ctx, resp, rec, rt)
	default:
		rp = s.respondBuffered(ctx, resp, rec, rt)
	}

	// 5. Meter, then audit, then (for buffered replies) respond.
	if rec.usage.TotalTokens == 0 && resp.StatusCode < 400 {
		rec.usage.PromptTokens = estPrompt
		rec.usage.TotalTokens = estPrompt + rec.usage.CompletionTokens
		rec.estimated = true
	}
	rec.cost = rec.model.Cost(rec.usage.PromptTokens, rec.usage.CompletionTokens)
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	charged = true
	if err := s.limiter.Record(mctx, rt.estate, subject, res, rec.cost, rec.usage.TotalTokens, rec.usage.TotalTokens-estPrompt); err != nil {
		s.log.Error("metering failed", "err", err, "request_id", rec.id)
	}
	if rp == nil {
		// Already streamed to the client; the record still has to land.
		if rec.decision == "" {
			rec.decision = strongestDecision(rec.findings)
		}
		s.writeAudit(ctx, rec.auditRecord(resource)) //nolint:errcheck
		return
	}
	s.conclude(w, ctx, rec, resource, rp)
}

// choiceTexts collects the texts of every choice in a completion.
func choiceTexts(out map[string]any) []textRef {
	var refs []textRef
	if choices, ok := out["choices"].([]any); ok {
		for _, ch := range choices {
			if c, ok := ch.(map[string]any); ok {
				if msg, ok := c["message"].(map[string]any); ok {
					refs = append(refs, messageTexts([]any{msg})...)
				}
			}
		}
	}
	return refs
}

// respondBuffered checks a non-streaming completion.
func (s *Server) respondBuffered(ctx context.Context, resp *http.Response, rec *requestRecord, rt *runtime) *reply {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		rec.decision, rec.status, rec.reasons = audit.Error, http.StatusBadGateway, []string{"reading upstream: " + err.Error()}
		return errorReply(http.StatusBadGateway, "server_error", "dataplane_error", "Chautari: upstream response unreadable")
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		rec.decision, rec.status, rec.reasons = audit.Error, http.StatusBadGateway, []string{"upstream returned invalid JSON"}
		return errorReply(http.StatusBadGateway, "server_error", "dataplane_error", "Chautari: upstream returned invalid JSON")
	}
	if u, ok := out["usage"]; ok {
		b, _ := json.Marshal(u)
		json.Unmarshal(b, &rec.usage) //nolint:errcheck
	}
	refs := choiceTexts(out)
	res, err := rt.guardrails.Inspect(ctx, rec.c.team.Name, estate.Outbound, readTexts(refs))
	rec.findings = append(rec.findings, res.Findings...)
	if err == nil && res.Blocked {
		err = errors.New(res.Reason)
	}
	if err != nil {
		rec.decision, rec.status, rec.reasons = audit.Block, http.StatusBadGateway, []string{err.Error()}
		return errorReply(http.StatusBadGateway, "server_error", "guardrail_blocked_response", "Chautari guardrail withheld the model's response: "+err.Error())
	}
	for i, t := range res.Texts {
		refs[i].set(t)
	}
	rec.status = http.StatusOK
	b, _ := json.Marshal(out)
	return &reply{status: http.StatusOK, header: http.Header{"Content-Type": {"application/json"}}, body: b}
}

// chunk is the slice of a streamed chat.completion.chunk Chautari reads.
type chunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content   string `json:"content"`
			Refusal   string `json:"refusal"`
			ToolCalls []struct {
				Index    int `json:"index"`
				Function struct {
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
	} `json:"choices"`
	Usage *usage `json:"usage"`
}

// streamText accumulates everything a stream says, per choice.
type streamText struct {
	id, model string
	content   map[int]*strings.Builder
	other     map[string]*strings.Builder // refusals and tool call arguments
	bytes     int
}

func newStreamText() *streamText {
	return &streamText{content: map[int]*strings.Builder{}, other: map[string]*strings.Builder{}}
}

func (st *streamText) add(data []byte, rec *requestRecord) {
	var ch chunk
	if json.Unmarshal(data, &ch) != nil {
		return
	}
	if ch.ID != "" {
		st.id, st.model = ch.ID, ch.Model
	}
	if ch.Usage != nil {
		rec.usage = *ch.Usage
	}
	sb := func(m map[string]*strings.Builder, k string) *strings.Builder {
		if m[k] == nil {
			m[k] = &strings.Builder{}
		}
		return m[k]
	}
	for _, c := range ch.Choices {
		if st.content[c.Index] == nil {
			st.content[c.Index] = &strings.Builder{}
		}
		st.content[c.Index].WriteString(c.Delta.Content)
		if c.Delta.Refusal != "" {
			sb(st.other, fmt.Sprintf("%d/refusal", c.Index)).WriteString(c.Delta.Refusal)
		}
		for _, tc := range c.Delta.ToolCalls {
			if tc.Function.Arguments != "" {
				sb(st.other, fmt.Sprintf("%d/tool/%d", c.Index, tc.Index)).WriteString(tc.Function.Arguments)
			}
		}
		st.bytes += len(c.Delta.Content) + len(c.Delta.Refusal)
	}
}

// texts returns content texts (by choice index) followed by everything else.
func (st *streamText) texts() (content []int, all []string) {
	for i := range st.content {
		content = append(content, i)
	}
	sort.Ints(content)
	for _, i := range content {
		all = append(all, st.content[i].String())
	}
	keys := make([]string, 0, len(st.other))
	for k := range st.other {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		all = append(all, st.other[k].String())
	}
	return content, all
}

// estimateCompletion fills in completion tokens from what was generated when
// the provider's usage never arrived.
func (st *streamText) estimateCompletion(rec *requestRecord) {
	if rec.usage.CompletionTokens == 0 && st.bytes > 0 {
		_, all := st.texts()
		rec.usage.CompletionTokens = estimateTokens(strings.Join(all, ""))
		rec.estimated = true
	}
}

// streamThrough relays SSE as it arrives. If the client goes away, it keeps
// reading upstream so the usage the provider bills is the usage we meter.
func (s *Server) streamThrough(w http.ResponseWriter, resp *http.Response, rec *requestRecord) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Chautari-Decision", strongestDecision(rec.findings))
	w.WriteHeader(http.StatusOK)
	rec.status = http.StatusOK
	flusher, _ := w.(http.Flusher)
	st := newStreamText()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), maxBody)
	gone := false
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("data:")) {
			st.add(bytes.TrimSpace(line[5:]), rec)
		}
		if gone {
			continue
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			gone, rec.disconnect = true, true
			continue
		}
		if len(line) == 0 && flusher != nil {
			flusher.Flush()
		}
	}
	if err := sc.Err(); err != nil {
		rec.reasons = append(rec.reasons, "upstream stream ended abnormally: "+err.Error())
	}
	if flusher != nil && !gone {
		flusher.Flush()
	}
	st.estimateCompletion(rec)
}

// streamBuffered collects the whole stream, runs outbound guardrails over
// everything it says (content, refusals, tool call arguments), and only then
// replays it. A guardrail that runs after the bytes have left is not a
// guardrail.
func (s *Server) streamBuffered(ctx context.Context, resp *http.Response, rec *requestRecord, rt *runtime) *reply {
	var raw bytes.Buffer
	st := newStreamText()
	sc := bufio.NewScanner(io.TeeReader(io.LimitReader(resp.Body, maxBody+1), &raw))
	sc.Buffer(make([]byte, 64*1024), maxBody)
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("data:")) {
			st.add(bytes.TrimSpace(line[5:]), rec)
		}
	}
	if err := sc.Err(); err != nil || raw.Len() > maxBody {
		st.estimateCompletion(rec)
		rec.decision, rec.status, rec.reasons = audit.Error, http.StatusBadGateway, []string{"upstream stream unreadable or too large"}
		return errorReply(http.StatusBadGateway, "server_error", "dataplane_error", "Chautari: upstream stream failed")
	}
	st.estimateCompletion(rec)
	contentIdx, texts := st.texts()
	res, err := rt.guardrails.Inspect(ctx, rec.c.team.Name, estate.Outbound, texts)
	rec.findings = append(rec.findings, res.Findings...)
	if err == nil && res.Blocked {
		err = errors.New(res.Reason)
	}
	if err == nil && res.Redacted() {
		// Content can be re-emitted redacted. Tool call arguments and refusals
		// can't be re-chunked faithfully, so a redaction there blocks.
		for i := len(contentIdx); i < len(texts); i++ {
			if res.Texts[i] != texts[i] {
				err = errors.New("redaction required inside streamed tool call arguments; withheld")
			}
		}
	}
	if err != nil {
		rec.decision, rec.status, rec.reasons = audit.Block, http.StatusBadGateway, []string{err.Error()}
		return errorReply(http.StatusBadGateway, "server_error", "guardrail_blocked_response", "Chautari guardrail withheld the model's response: "+err.Error())
	}
	rec.status = http.StatusOK
	hdr := http.Header{"Content-Type": {"text/event-stream"}, "Cache-Control": {"no-cache"}}
	if !res.Redacted() {
		return &reply{status: http.StatusOK, header: hdr, body: raw.Bytes()}
	}
	// The content changed: re-emit it as one delta per choice, same envelope.
	var b bytes.Buffer
	emit := func(v any) {
		j, _ := json.Marshal(v)
		fmt.Fprintf(&b, "data: %s\n\n", j)
	}
	created := time.Now().Unix()
	for n, idx := range contentIdx {
		emit(map[string]any{"id": st.id, "object": "chat.completion.chunk", "created": created, "model": st.model,
			"choices": []any{map[string]any{"index": idx, "delta": map[string]any{"role": "assistant", "content": res.Texts[n]}, "finish_reason": nil}}})
		emit(map[string]any{"id": st.id, "object": "chat.completion.chunk", "created": created, "model": st.model,
			"choices": []any{map[string]any{"index": idx, "delta": map[string]any{}, "finish_reason": "stop"}}})
	}
	emit(map[string]any{"id": st.id, "object": "chat.completion.chunk", "created": created, "model": st.model,
		"choices": []any{}, "usage": rec.usage})
	b.WriteString("data: [DONE]\n\n")
	return &reply{status: http.StatusOK, header: hdr, body: b.Bytes()}
}

// models lists the models the caller's team may use right now.
func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	rt := s.runtime()
	c, err := s.authenticate(r.Context(), r, rt)
	if err != nil {
		s.authError(w, err)
		return
	}
	data := []any{}
	for _, name := range c.team.Models {
		if !rt.approvals.Models[name] {
			continue
		}
		m, _ := rt.estate.Model(name)
		data = append(data, map[string]any{"id": name, "object": "model", "created": 0, "owned_by": m.Provider,
			"chautari": map[string]any{"data_class": m.DataClass, "risk_tier": m.RiskTier}})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data}) //nolint:errcheck
}

// authorizeTool answers "may I call this tool?" for agents that ask first,
// and for data planes without native MCP authorization.
func (s *Server) authorizeTool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt := s.runtime()
	c, err := s.authenticate(ctx, r, rt)
	if err != nil {
		s.authError(w, err)
		return
	}
	var req struct {
		Server string `json:"server"`
		Tool   string `json:"tool"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Server == "" {
		apiError(w, http.StatusBadRequest, "invalid_request_error", "invalid_request", `Chautari: body must be {"server": "...", "tool": "..."}`)
		return
	}
	d, ok := s.decideTool(w, ctx, c, req.Server, req.Tool, s.dataClass(r, c, rt), "authorize")
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d) //nolint:errcheck
}

// decideTool evaluates and audits a tool call. If the decision cannot be
// recorded it answers 503 and returns ok=false.
func (s *Server) decideTool(w http.ResponseWriter, ctx context.Context, c caller, server, tool, dataClass, via string) (policy.Decision, bool) {
	d := s.policy.Decide(ctx, policy.Input{
		Subject:   policy.Subject{Team: c.team.Name, App: c.app.Name, Key: c.key.ID},
		Action:    policy.ActionTool,
		Resource:  policy.Resource{Name: server, Tool: tool},
		DataClass: dataClass,
	})
	decision := audit.Allow
	if !d.Allow {
		decision = audit.Deny
	}
	ok := s.mustAudit(w, ctx, audit.Record{Kind: audit.KindTool, Actor: c.key.ID, Subject: c.team.Name + "/" + c.app.Name,
		Action: policy.ActionTool, Resource: "tool/" + server + "/" + tool, Decision: decision, Reasons: d.Reasons,
		Details: map[string]any{"via": via, "data_class": dataClass}})
	return d, ok
}
