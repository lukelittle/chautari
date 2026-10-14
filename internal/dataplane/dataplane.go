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

// Package dataplane abstracts the gateway that actually carries traffic.
//
// Chautari is a control plane: it decides, meters and records, but it does
// not talk to model providers itself. An Adapter renders configuration for a
// data plane (agentgateway by default, LiteLLM as an alternative) and
// forwards admitted requests to it.
package dataplane

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lukelittle/chautari/internal/estate"
)

// Headers the checkpoint sets on forwarded traffic. The data plane only
// accepts requests carrying the internal key, so these are trustworthy there.
const (
	HeaderTeam  = "X-Chautari-Team"
	HeaderApp   = "X-Chautari-App"
	HeaderAgent = "X-Chautari-Agent"
)

// File is a rendered configuration file, relative to the data plane's config
// directory.
type File struct {
	Path    string
	Content []byte
}

// State is the live registry state that, together with the estate, decides
// what the data plane should expose. A nil map means "use the CDL flags".
type State struct {
	Models map[string]bool // model name -> approved
	Tools  map[string]bool
	Agents map[string]bool
}

// ModelApproved resolves a model's approval from live state or the estate.
func (s State) ModelApproved(m estate.Model) bool {
	if s.Models == nil {
		return m.Approved
	}
	return s.Models[m.Name]
}

// ToolApproved resolves a tool's approval from live state or the estate.
func (s State) ToolApproved(t estate.Tool) bool {
	if s.Tools == nil {
		return t.Approved
	}
	return s.Tools[t.Name]
}

// AgentApproved resolves an agent's approval from live state or the estate.
func (s State) AgentApproved(a estate.Agent) bool {
	if s.Agents == nil {
		return a.Approved
	}
	return s.Agents[a.Name]
}

// Options configure rendering and forwarding.
type Options struct {
	// BaseURL is where the data plane listens for LLM traffic,
	// e.g. http://agentgateway:3000.
	BaseURL string
	// MCPURL is the data plane's MCP endpoint, e.g. http://agentgateway:3000/mcp.
	MCPURL string
	// A2AURL is the data plane's A2A listener, e.g. http://agentgateway:3100.
	A2AURL string
	// InternalKey authenticates the checkpoint to the data plane.
	InternalKey string
	// OTLPEndpoint, if set, is written into the data plane's tracing config.
	OTLPEndpoint string
	// Timeout bounds a forwarded request. Zero means two minutes.
	Timeout time.Duration
	// Transport, if set, carries forwarded requests (e.g. with tracing).
	Transport http.RoundTripper
}

// Adapter is a data plane implementation.
type Adapter interface {
	// Name identifies the adapter ("agentgateway", "litellm", "direct").
	Name() string
	// Render produces the data plane's configuration files.
	Render(e *estate.Estate, s State) ([]File, error)
	// ChatCompletions forwards an admitted OpenAI chat completion request.
	// The upstream model name has already been substituted into body.
	ChatCompletions(ctx context.Context, body []byte, meta Meta) (*http.Response, error)
	// MCPTarget is the URL MCP traffic is proxied to, or "" if unsupported.
	MCPTarget() string
	// A2ATarget is the URL for an agent's A2A traffic, or "" if unsupported.
	A2ATarget(agent string) string
}

// Meta identifies who a forwarded request is for.
type Meta struct {
	Team, App, Model, RequestID string
}

// New returns the adapter for the given name.
func New(name string, opts Options) (Adapter, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute
	}
	client := &http.Client{Timeout: opts.Timeout, Transport: opts.Transport}
	switch name {
	case "agentgateway", "":
		return &AgentGateway{opts: opts, client: client}, nil
	case "litellm":
		return &LiteLLM{opts: opts, client: client}, nil
	case "direct":
		return &Direct{opts: opts, client: client}, nil
	}
	return nil, fmt.Errorf("unknown data plane %q (want agentgateway, litellm or direct)", name)
}

// forward POSTs an OpenAI-format body to base + path.
func forward(ctx context.Context, client *http.Client, base, path, key string, body []byte, meta Meta) (*http.Response, error) {
	u, err := url.JoinPath(base, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	setMeta(req.Header, meta)
	return client.Do(req)
}

func setMeta(h http.Header, meta Meta) {
	if meta.Team != "" {
		h.Set(HeaderTeam, meta.Team)
	}
	if meta.App != "" {
		h.Set(HeaderApp, meta.App)
	}
	if meta.RequestID != "" {
		h.Set("X-Request-Id", meta.RequestID)
	}
}

// Direct forwards straight to an OpenAI-compatible endpoint. It renders no
// configuration and exists for tests and local hacking.
type Direct struct {
	opts   Options
	client *http.Client
}

func (d *Direct) Name() string                                 { return "direct" }
func (d *Direct) Render(*estate.Estate, State) ([]File, error) { return nil, nil }
func (d *Direct) MCPTarget() string                            { return d.opts.MCPURL }
func (d *Direct) A2ATarget(string) string                      { return d.opts.A2AURL }
func (d *Direct) ChatCompletions(ctx context.Context, body []byte, meta Meta) (*http.Response, error) {
	return forward(ctx, d.client, d.opts.BaseURL, "/chat/completions", d.opts.InternalKey, body, meta)
}

// InternalKey returns the key the checkpoint presents to the data plane.
func (a *AgentGateway) InternalKey() string { return a.opts.InternalKey }

// InternalKey returns the key the checkpoint presents to the data plane.
func (l *LiteLLM) InternalKey() string { return l.opts.InternalKey }

// InternalKey returns the key the checkpoint presents to the data plane.
func (d *Direct) InternalKey() string { return d.opts.InternalKey }
