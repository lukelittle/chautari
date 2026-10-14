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

// Package mockllm is an offline stand-in for every upstream Chautari talks to:
// an OpenAI-compatible LLM API, an MCP server (Streamable HTTP, JSON-RPC 2.0)
// and an A2A agent. All responses are deterministic, so tests can assert on
// exact bodies and token counts without a real model.
//
// Magic markers in the last user message trigger demo and failure behaviour;
// see the Marker constants.
package mockllm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// Magic markers recognised in the last user message of a chat completion.
const (
	// MarkerLeakSSN appends LeakSSN to the reply.
	MarkerLeakSSN = "[[leak-ssn]]"
	// MarkerLeakCard appends LeakCard to the reply.
	MarkerLeakCard = "[[leak-card]]"
	// MarkerLeakEmail appends LeakEmail to the reply.
	MarkerLeakEmail = "[[leak-email]]"
	// MarkerError makes the completion fail with HTTP 500.
	MarkerError = "[[error]]"
	// MarkerSlow delays the reply by Options.SlowDelay (default 2s).
	MarkerSlow = "[[slow]]"
	// MarkerLong replaces the reply with a ~2000 word text.
	MarkerLong = "[[long]]"
)

// Sentences appended to the reply by the leak markers.
const (
	LeakSSN   = "The customer's SSN is 123-45-6789."
	LeakCard  = "Card on file: 4111 1111 1111 1111."
	LeakEmail = "Contact jane.doe@example.com."
)

// DefaultSlowDelay is the delay applied by MarkerSlow when Options.SlowDelay is zero.
const DefaultSlowDelay = 2 * time.Second

// DefaultCreated is the `created` timestamp used when Options.Now is nil
// (2025-01-01T00:00:00Z), keeping response bodies byte-for-byte deterministic.
const DefaultCreated int64 = 1735689600

// Models is the fixed list served by GET /v1/models. Completions accept any model id.
var Models = []string{"claude-sonnet-4-5", "claude-haiku-4-5", "gpt-4o", "llama-3.3-70b"}

// Options configures the mock.
type Options struct {
	// APIKey, if non-empty, is required as `Authorization: Bearer <key>` on /v1/*.
	APIKey string
	// SlowDelay is the delay for MarkerSlow. Zero means DefaultSlowDelay.
	SlowDelay time.Duration
	// Latency is added before every chat completion response. Zero means none.
	Latency time.Duration
	// Now supplies `created` timestamps. Nil means the fixed DefaultCreated.
	Now func() time.Time
}

type server struct {
	opts Options
}

// New returns the mock's http.Handler serving /v1/*, /mcp, the A2A agent at /
// and /.well-known/agent(-card).json, and /healthz.
func New(opts Options) http.Handler {
	if opts.SlowDelay == 0 {
		opts.SlowDelay = DefaultSlowDelay
	}
	s := &server{opts: opts}
	mux := http.NewServeMux()

	v1 := http.NewServeMux()
	v1.HandleFunc("GET /v1/models", s.handleModels)
	v1.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	v1.HandleFunc("/v1/", handleV1NotFound)
	mux.Handle("/v1/", s.requireKey(v1))

	mux.HandleFunc("POST /mcp", s.handleMCP)
	mux.HandleFunc("/mcp", handleMCPMethodNotAllowed)

	mux.HandleFunc("GET /.well-known/agent-card.json", handleAgentCard)
	mux.HandleFunc("GET /.well-known/agent.json", handleAgentCard)
	mux.HandleFunc("POST /{$}", handleA2A)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// EstimateTokens is the mock's token estimate: ceil(runes/4), minimum 1.
// Usage is computed with it, so callers can predict costs exactly:
// prompt_tokens = EstimateTokens(concatenation of all message contents),
// completion_tokens = EstimateTokens(reply).
func EstimateTokens(s string) int {
	n := (utf8.RuneCountInString(s) + 3) / 4
	return max(n, 1)
}

func (s *server) requireKey(next http.Handler) http.Handler {
	if s.opts.APIKey == "" {
		return next
	}
	want := "Bearer " + s.opts.APIKey
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			writeOpenAIError(w, http.StatusUnauthorized, "invalid_request_error", "invalid_api_key",
				"Incorrect API key provided.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleV1NotFound(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/models", "/v1/chat/completions":
		writeOpenAIError(w, http.StatusMethodNotAllowed, "invalid_request_error", "method_not_allowed",
			"Method "+r.Method+" not allowed on "+r.URL.Path+".")
	default:
		writeOpenAIError(w, http.StatusNotFound, "invalid_request_error", "unknown_url",
			"Unknown request URL: "+r.Method+" "+r.URL.Path+".")
	}
}

// sleepCtx waits for d or until ctx is done, returning ctx.Err() in the latter case.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// shortHash returns the first n hex characters of sha256 over parts joined by NUL.
func shortHash(n int, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:n]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
