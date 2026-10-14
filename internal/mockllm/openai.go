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
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// cannedReplies are chosen by a stable hash of the last user message.
var cannedReplies = []string{
	"Happy to help. Based on the account history, the customer is in good standing and no further action is needed today.",
	"The overnight batch completed successfully. All 1,204 payments settled and reconciliation shows no breaks.",
	"Here is a short summary: the loan application is complete, income is verified, and it is ready for underwriting review.",
	"I checked the incident timeline. The latency spike was caused by a cache warm-up after deploy and has since recovered.",
	"The wire transfer is within the customer's daily limit and passed sanctions screening, so it can be released.",
	"Good question. Fixed-rate mortgages keep the payment stable, while variable rates track the base rate and can move either way.",
	"The quarterly controls attestation is on track. Two evidence items are outstanding and owners have been notified.",
	"Sure. I would recommend opening a high-yield savings account for the emergency fund and keeping three months of expenses there.",
}

// longParagraph is repeated to build the MarkerLong reply (~100 words each).
const longParagraph = "This section reviews the operating position in detail. Deposits grew steadily across retail and commercial segments, " +
	"while loan origination held flat against a tighter rate environment. Credit quality remains sound, with delinquencies " +
	"below the five year average and no single sector showing concentration stress. Operational resilience improved after " +
	"the payments platform migration, and incident volumes fell for the third consecutive month. The risk committee asked " +
	"for further work on model validation, vendor oversight and data lineage. Management agreed to deliver an updated plan, " +
	"with named owners and dates, before the next quarterly review of the control environment."

const longSections = 20

type chatRequest struct {
	Model         string        `json:"model"`
	Messages      []chatMessage `json:"messages"`
	Stream        bool          `json:"stream"`
	StreamOptions *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type contentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Usage is the OpenAI usage object.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type outMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type choice struct {
	Index        int        `json:"index"`
	Message      outMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type chatCompletion struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type delta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

type chunkChoice struct {
	Index        int     `json:"index"`
	Delta        delta   `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

type chatChunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []chunkChoice `json:"choices"`
	Usage   *Usage        `json:"usage,omitempty"`
}

// completion is the parsed, resolved outcome of a chat request.
type completion struct {
	id     string
	model  string
	reply  string
	usage  Usage
	prompt string // last user message
}

func (s *server) handleModels(w http.ResponseWriter, _ *http.Request) {
	type model struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}
	data := make([]model, len(Models))
	for i, id := range Models {
		data[i] = model{ID: id, Object: "model", Created: DefaultCreated, OwnedBy: "chautari-mock"}
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func (s *server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20))
	if err := dec.Decode(&req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "invalid_json",
			"We could not parse the JSON body of your request: "+err.Error())
		return
	}
	c, err := resolve(&req)
	if err != nil {
		var re *requestError
		if errors.As(err, &re) {
			writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", re.code, re.msg)
			return
		}
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "invalid_request", err.Error())
		return
	}

	if strings.Contains(c.prompt, MarkerError) {
		writeOpenAIError(w, http.StatusInternalServerError, "server_error", "mock_error",
			"The mock provider failed on purpose ([[error]] marker).")
		return
	}
	delay := s.opts.Latency
	if strings.Contains(c.prompt, MarkerSlow) {
		delay += s.opts.SlowDelay
	}
	if err := sleepCtx(r.Context(), delay); err != nil {
		return // client went away
	}

	created := DefaultCreated
	if s.opts.Now != nil {
		created = s.opts.Now().Unix()
	}
	if req.Stream {
		includeUsage := req.StreamOptions != nil && req.StreamOptions.IncludeUsage
		writeStream(w, c, created, includeUsage)
		return
	}
	writeJSON(w, http.StatusOK, chatCompletion{
		ID:      c.id,
		Object:  "chat.completion",
		Created: created,
		Model:   c.model,
		Choices: []choice{{Message: outMessage{Role: "assistant", Content: c.reply}, FinishReason: "stop"}},
		Usage:   c.usage,
	})
}

type requestError struct{ code, msg string }

func (e *requestError) Error() string { return e.msg }

// resolve validates the request and computes the deterministic reply and usage.
func resolve(req *chatRequest) (*completion, error) {
	if req.Model == "" {
		return nil, &requestError{"missing_model", "you must provide a model parameter"}
	}
	if len(req.Messages) == 0 {
		return nil, &requestError{"missing_messages", "'messages' must be a non-empty array"}
	}
	var all strings.Builder
	var lastUser string
	for i, m := range req.Messages {
		text, err := messageText(m.Content)
		if err != nil {
			return nil, &requestError{"invalid_content", fmt.Sprintf("messages[%d].content: %v", i, err)}
		}
		all.WriteString(text)
		if m.Role == "user" {
			lastUser = text
		}
	}
	reply := Reply(lastUser)
	usage := Usage{PromptTokens: EstimateTokens(all.String()), CompletionTokens: EstimateTokens(reply)}
	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	return &completion{
		id:     "chatcmpl-mock-" + shortHash(12, req.Model, all.String()),
		model:  req.Model,
		reply:  reply,
		usage:  usage,
		prompt: lastUser,
	}, nil
}

// messageText flattens a message content that is a string, an array of
// {type:"text"} parts, or null. Non-text parts are ignored.
func messageText(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", nil
	}
	if raw[0] == '"' {
		var s string
		err := json.Unmarshal(raw, &s)
		return s, err
	}
	if raw[0] == '[' {
		var parts []contentPart
		if err := json.Unmarshal(raw, &parts); err != nil {
			return "", err
		}
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "text" {
				b.WriteString(p.Text)
			}
		}
		return b.String(), nil
	}
	return "", errors.New("must be a string or an array of content parts")
}

// Reply returns the deterministic assistant reply for a last user message,
// including any text added by the magic markers. MarkerError and MarkerSlow do
// not change the text.
func Reply(prompt string) string {
	var reply string
	if strings.Contains(prompt, MarkerLong) {
		reply = longReply()
	} else {
		sum := sha256.Sum256([]byte(prompt))
		reply = cannedReplies[int(sum[0])%len(cannedReplies)]
	}
	for _, leak := range []struct{ marker, text string }{
		{MarkerLeakSSN, LeakSSN},
		{MarkerLeakCard, LeakCard},
		{MarkerLeakEmail, LeakEmail},
	} {
		if strings.Contains(prompt, leak.marker) {
			reply += " " + leak.text
		}
	}
	return reply
}

func longReply() string {
	parts := make([]string, longSections)
	for i := range parts {
		parts[i] = fmt.Sprintf("Section %d. %s", i+1, longParagraph)
	}
	return strings.Join(parts, "\n\n")
}

// writeStream emits the reply as OpenAI chat.completion.chunk SSE events.
func writeStream(w http.ResponseWriter, c *completion, created int64, includeUsage bool) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	send := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	chunk := func(d delta, finish *string) chatChunk {
		return chatChunk{
			ID: c.id, Object: "chat.completion.chunk", Created: created, Model: c.model,
			Choices: []chunkChoice{{Delta: d, FinishReason: finish}},
		}
	}

	send(chunk(delta{Role: "assistant"}, nil))
	for _, piece := range splitChunks(c.reply, 3) {
		send(chunk(delta{Content: piece}, nil))
	}
	stop := "stop"
	send(chunk(delta{}, &stop))
	if includeUsage {
		u := c.usage
		send(chatChunk{
			ID: c.id, Object: "chat.completion.chunk", Created: created, Model: c.model,
			Choices: []chunkChoice{}, Usage: &u,
		})
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

// splitChunks splits s into pieces of up to n words each. Concatenating the
// pieces reproduces s exactly (whitespace stays with the preceding piece).
func splitChunks(s string, n int) []string {
	var out []string
	start, words := 0, 0
	inWord := false
	for i, r := range s {
		space := r == ' ' || r == '\n' || r == '\t'
		if !space && !inWord {
			if words == n {
				out = append(out, s[start:i])
				start, words = i, 0
			}
			words++
		}
		inWord = !space
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func writeOpenAIError(w http.ResponseWriter, status int, typ, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": msg, "type": typ, "param": nil, "code": code},
	})
}
