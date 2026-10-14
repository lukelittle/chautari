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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/estate"
)

func loadExample(t *testing.T) *estate.Estate {
	t.Helper()
	e, err := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// agentgatewaySchema compiles the vendored upstream JSON schema.
func agentgatewaySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open("testdata/agentgateway-v1.6.0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("agentgateway.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("agentgateway.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// yamlToJSONValue converts YAML into the generic form the validator expects.
func yamlToJSONValue(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jsonschema.UnmarshalJSON(strings.NewReader(string(j)))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func renderAGW(t *testing.T, e *estate.Estate, s State) string {
	t.Helper()
	a, _ := New("agentgateway", Options{BaseURL: "http://agentgateway:3000", A2AURL: "http://agentgateway:3100", OTLPEndpoint: "http://otel-collector:4317"})
	files, err := a.Render(e, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "gateway.yaml" {
		t.Fatalf("files = %v", files)
	}
	return string(files[0].Content)
}

func TestAgentGatewayConfigMatchesUpstreamSchema(t *testing.T) {
	schema := agentgatewaySchema(t)
	e := loadExample(t)
	for name, st := range map[string]State{
		"cdl flags":    {},
		"all approved": {Models: map[string]bool{"claude-sonnet": true, "claude-haiku": true, "gpt-4o": true, "llama-70b": true}, Tools: map[string]bool{"jira-mcp": true, "core-banking-mcp": true}, Agents: map[string]bool{"underwriting-agent": true}},
		"nothing":      {Models: map[string]bool{}, Tools: map[string]bool{}, Agents: map[string]bool{}},
	} {
		t.Run(name, func(t *testing.T) {
			y := renderAGW(t, e, st)
			if err := schema.Validate(yamlToJSONValue(t, []byte(y))); err != nil {
				t.Fatalf("rendered config fails agentgateway %s schema:\n%v\n---\n%s", AgentGatewayVersion, err, y)
			}
		})
	}
}

func TestAgentGatewayRenderContent(t *testing.T) {
	e := loadExample(t)
	y := renderAGW(t, e, State{})

	mustContain := []string{
		"${CHAUTARI_GATEWAY_KEY}",          // internal key, expanded by the gateway
		"name: claude-sonnet",              // approved model
		"model: claude-sonnet-4-5",         // upstream id
		"baseUrl: http://mock-llm:8090/v1", // openai-compatible provider
		"${MOCK_API_KEY:-unused}",          // optional key with default
		`mcp.tool.target == "jira-mcp"`,    // CEL entitlement
		`mcp.tool.name in ["get_issue", "search_issues"]`,
		"pathPrefix: /a2a/underwriting-agent",
		"otlpEndpoint: http://otel-collector:4317",
	}
	for _, s := range mustContain {
		if !strings.Contains(y, s) {
			t.Errorf("gateway.yaml missing %q\n%s", s, y)
		}
	}
	mustNot := []string{
		"llama-3.3-70b",    // not approved: must not be routable
		"core-banking-mcp", // not approved
	}
	for _, s := range mustNot {
		if strings.Contains(y, s) {
			t.Errorf("gateway.yaml must not contain %q", s)
		}
	}
	// Only the wealth team lacks jira-mcp; it must not get a rule.
	if strings.Contains(y, `"wealth"`) {
		t.Errorf("wealth must not be entitled to any tool:\n%s", y)
	}
}

func TestAgentGatewayRetireRemovesModel(t *testing.T) {
	e := loadExample(t)
	y := renderAGW(t, e, State{Models: map[string]bool{"claude-haiku": true}})
	if strings.Contains(y, "claude-sonnet-4-5") || !strings.Contains(y, "claude-haiku-4-5") {
		t.Fatalf("retired model still routable:\n%s", y)
	}
}

func TestAgentGatewayRenderDeterministic(t *testing.T) {
	e := loadExample(t)
	a, b := renderAGW(t, e, State{}), renderAGW(t, e, State{})
	if a != b {
		t.Fatal("render is not deterministic")
	}
}

// shellexpand mimics the expansion agentgateway applies to its whole config
// file (shellexpand::full): $$ is a literal '$', ${NAME}, ${NAME:-default}
// and $NAME are replaced, and an unset variable without a default is an error.
func shellexpand(s string, env map[string]string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		var name, def string
		hasDef := false
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${ at %d", i)
			}
			name = s[i+2 : i+end]
			if k := strings.Index(name, ":-"); k >= 0 {
				name, def, hasDef = name[:k], name[k+2:], true
			}
			i += end
		} else {
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j == i+1 {
				b.WriteByte('$')
				continue
			}
			name = s[i+1 : j]
			i = j - 1
		}
		v, ok := env[name]
		if !ok || v == "" && hasDef {
			if !hasDef {
				return "", fmt.Errorf("LookupError %s", name)
			}
			v = def
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

func TestEstateStringsCannotTriggerShellExpansion(t *testing.T) {
	// Built directly, bypassing the compiler: models requested over the API
	// reach the renderer this way, so the renderer must be safe on its own.
	e := &estate.Estate{
		DefaultDataClass: estate.Internal,
		Providers: []estate.Provider{
			{Name: "evil", Type: "openai-compatible", Endpoint: "http://evil.example/${CHAUTARI_GATEWAY_KEY}/v1", APIKeyEnv: "EVIL_API_KEY"},
			{Name: "gcp", Type: "vertex", Region: "europe-west4"},
		},
		Models: []estate.Model{
			{Name: "m", Provider: "evil", UpstreamID: "cost$5-${OPENAI_API_KEY}", Approved: true},
			{Name: "v", Provider: "gcp", UpstreamID: "gemini", Approved: true},
		},
		Tools: []estate.Tool{{Name: "jira", Endpoint: "http://jira/$HOME/mcp", Allow: []string{"get_issue", "cost$5"}, Approved: true}},
		Teams: []estate.Team{{Name: "t", Models: []string{"m", "v"}, Tools: []string{"jira"}}},
	}
	y := renderAGW(t, e, State{})
	env := map[string]string{"CHAUTARI_GATEWAY_KEY": "SECRET-GATEWAY", "OPENAI_API_KEY": "SECRET-OPENAI", "HOME": "/root", "EVIL_API_KEY": "k"}
	expanded, err := shellexpand(strings.ReplaceAll(y, "# yaml-language-server: $schema", "#"), env)
	if err != nil {
		t.Fatalf("config must load even with hostile strings: %v\n%s", err, y)
	}
	if strings.Contains(expanded, "evil.example/SECRET") || strings.Contains(expanded, "SECRET-OPENAI") || strings.Contains(expanded, "/root") {
		t.Fatalf("estate data triggered expansion:\n%s", expanded)
	}
	for _, literal := range []string{"http://evil.example/${CHAUTARI_GATEWAY_KEY}/v1", "cost$5-${OPENAI_API_KEY}", "http://jira/$HOME/mcp", `"cost$5"`} {
		if !strings.Contains(expanded, literal) {
			t.Errorf("literal %q did not survive expansion", literal)
		}
	}
	// Chautari's own references still expand.
	if !strings.Contains(expanded, "key: SECRET-GATEWAY") {
		t.Fatalf("internal key reference broken:\n%s", expanded)
	}
	// Vertex without GOOGLE_CLOUD_PROJECT must not stop the gateway loading.
	if !strings.Contains(y, "${GOOGLE_CLOUD_PROJECT:-}") {
		t.Fatalf("vertex project must have a default:\n%s", y)
	}
	if err := agentgatewaySchema(t).Validate(yamlToJSONValue(t, []byte(y))); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

func TestA2ABackends(t *testing.T) {
	cases := []struct {
		in, host, path string
		tls            bool
	}{
		{"mock-llm:8090", "mock-llm:8090", "/", false},
		{"http://agent.internal", "agent.internal:80", "/", false},
		{"https://agent.example.com/a2a/v1", "agent.example.com:443", "/a2a/v1", true},
		{"https://agent.example.com:8443", "agent.example.com:8443", "/", true},
	}
	for _, c := range cases {
		h, p, tls := A2ABackend(c.in)
		if h != c.host || p != c.path || tls != c.tls {
			t.Errorf("%s → %s %s %v", c.in, h, p, tls)
		}
	}
	e := loadExample(t)
	e.Agents[0].Endpoint = "https://agent.example.com/a2a/v1"
	y := renderAGW(t, e, State{})
	for _, want := range []string{"host: agent.example.com:443", "prefix: /a2a/v1", "backendTLS: {}"} {
		if !strings.Contains(y, want) {
			t.Errorf("missing %q\n%s", want, y)
		}
	}
	if err := agentgatewaySchema(t).Validate(yamlToJSONValue(t, []byte(y))); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

func TestLiteLLMRender(t *testing.T) {
	a, _ := New("litellm", Options{BaseURL: "http://litellm:4000", OTLPEndpoint: "http://otel:4317"})
	files, err := a.Render(loadExample(t), State{})
	if err != nil {
		t.Fatal(err)
	}
	var cfg litellmConfig
	if err := yaml.Unmarshal(files[0].Content, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.ModelList) != 3 {
		t.Fatalf("want 3 approved models, got %d", len(cfg.ModelList))
	}
	m := cfg.ModelList[0]
	if m.ModelName != "claude-haiku" || m.Params.Model != "openai/claude-haiku-4-5" || m.Params.APIBase != "http://mock-llm:8090/v1" {
		t.Fatalf("model = %+v", m)
	}
	if cfg.GeneralSettings.MasterKey != "os.environ/CHAUTARI_GATEWAY_KEY" {
		t.Fatalf("master key = %q", cfg.GeneralSettings.MasterKey)
	}
	if a.MCPTarget() != "" || a.A2ATarget("x") != "" {
		t.Fatal("litellm has no MCP or A2A routing")
	}
}

func TestProviderMappings(t *testing.T) {
	src := `
provider br { type bedrock, region eu-west-1 }
provider oa { type openai }
provider an { type anthropic }
provider az { type azure, endpoint "https://myres.openai.azure.com" }
provider vx { type vertex, region europe-west4 }
model m1 { provider br, approved true }
model m2 { provider oa, approved true }
model m3 { provider an, approved true }
model m4 { provider az, approved true }
model m5 { provider vx, approved true }
team t { models [m1, m2, m3, m4, m5] }`
	e, err := cdl.Compile("p.cdl", src)
	if err != nil {
		t.Fatal(err)
	}
	y := renderAGW(t, e, State{})
	for _, s := range []string{"provider: bedrock", "awsRegion: eu-west-1", "provider: openAI", "${OA_API_KEY}", "provider: anthropic", "provider: azure", "azureResourceName: myres", "provider: vertex", "vertexRegion: europe-west4"} {
		if !strings.Contains(y, s) {
			t.Errorf("missing %q\n%s", s, y)
		}
	}
	if err := agentgatewaySchema(t).Validate(yamlToJSONValue(t, []byte(y))); err != nil {
		t.Fatalf("schema: %v", err)
	}
	l, _ := New("litellm", Options{})
	if _, err := l.Render(e, State{}); err != nil {
		t.Fatal(err)
	}
}

func TestForwardSetsInternalKeyAndMeta(t *testing.T) {
	var got *http.Request
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	for _, name := range []string{"agentgateway", "litellm"} {
		a, _ := New(name, Options{BaseURL: srv.URL, InternalKey: "internal-123"})
		resp, err := a.ChatCompletions(context.Background(), []byte(`{"model":"m"}`), Meta{Team: "lending", App: "loan-assistant", RequestID: "r1"})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got.URL.Path != "/v1/chat/completions" || got.Header.Get("Authorization") != "Bearer internal-123" ||
			got.Header.Get(HeaderTeam) != "lending" || got.Header.Get(HeaderApp) != "loan-assistant" || body != `{"model":"m"}` {
			t.Fatalf("%s forwarded %s %v %q", name, got.URL.Path, got.Header, body)
		}
	}
	d, _ := New("direct", Options{BaseURL: srv.URL + "/v1"})
	resp, err := d.ChatCompletions(context.Background(), []byte(`{}`), Meta{})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.URL.Path != "/v1/chat/completions" {
		t.Fatalf("direct path = %s", got.URL.Path)
	}
	if _, err := New("nope", Options{}); err == nil {
		t.Fatal("unknown adapter must error")
	}
}

func TestSchemaValidatorRejectsBadConfig(t *testing.T) {
	bad := "gateways:\n  default:\n    port: 3000\nllm:\n  models:\n  - name: x\n    provider: notAProvider\n"
	if err := agentgatewaySchema(t).Validate(yamlToJSONValue(t, []byte(bad))); err == nil {
		t.Fatal("validator accepted an unknown provider; the schema test would be meaningless")
	}
}
