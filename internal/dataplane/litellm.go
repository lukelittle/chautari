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
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lukelittle/chautari/internal/estate"
)

// LiteLLMImage is the LiteLLM proxy image the generator pins.
const LiteLLMImage = "ghcr.io/berriai/litellm:main-stable"

// LiteLLM renders a LiteLLM proxy config and forwards to it. LiteLLM has no
// equivalent of agentgateway's MCP authorization or A2A routing, so tools are
// governed through the checkpoint's /v1/tools/authorize only.
type LiteLLM struct {
	opts   Options
	client *http.Client
}

func (l *LiteLLM) Name() string            { return "litellm" }
func (l *LiteLLM) MCPTarget() string       { return "" }
func (l *LiteLLM) A2ATarget(string) string { return "" }

func (l *LiteLLM) ChatCompletions(ctx context.Context, body []byte, meta Meta) (*http.Response, error) {
	return forward(ctx, l.client, l.opts.BaseURL, "/v1/chat/completions", l.opts.InternalKey, body, meta)
}

type litellmConfig struct {
	ModelList       []litellmModel   `yaml:"model_list"`
	GeneralSettings litellmGeneral   `yaml:"general_settings"`
	LiteLLMSettings *litellmSettings `yaml:"litellm_settings,omitempty"`
}

type litellmModel struct {
	ModelName string        `yaml:"model_name"`
	Params    litellmParams `yaml:"litellm_params"`
}

type litellmParams struct {
	Model         string `yaml:"model"`
	APIBase       string `yaml:"api_base,omitempty"`
	APIKey        string `yaml:"api_key,omitempty"`
	AWSRegionName string `yaml:"aws_region_name,omitempty"`
	VertexProject string `yaml:"vertex_project,omitempty"`
	VertexLoc     string `yaml:"vertex_location,omitempty"`
}

type litellmGeneral struct {
	MasterKey string `yaml:"master_key"`
}

type litellmSettings struct {
	Callbacks []string `yaml:"callbacks"`
}

const litellmHeader = `# LiteLLM proxy configuration, rendered by Chautari. Do not edit.
# Secrets use LiteLLM's os.environ/ references.
`

// Render produces litellm.yaml.
func (l *LiteLLM) Render(e *estate.Estate, s State) ([]File, error) {
	cfg := litellmConfig{GeneralSettings: litellmGeneral{MasterKey: "os.environ/" + GatewayKeyEnv}}
	if l.opts.OTLPEndpoint != "" {
		cfg.LiteLLMSettings = &litellmSettings{Callbacks: []string{"otel"}}
	}
	for _, m := range e.Models {
		if !s.ModelApproved(m) {
			continue
		}
		p, ok := e.Provider(m.Provider)
		if !ok {
			return nil, fmt.Errorf("model %s: unknown provider %s", m.Name, m.Provider)
		}
		params, err := litellmParamsFor(p, m)
		if err != nil {
			return nil, err
		}
		cfg.ModelList = append(cfg.ModelList, litellmModel{ModelName: m.Name, Params: params})
	}
	var buf bytes.Buffer
	buf.WriteString(litellmHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return []File{{Path: "litellm.yaml", Content: buf.Bytes()}}, nil
}

func litellmParamsFor(p estate.Provider, m estate.Model) (litellmParams, error) {
	key := ""
	if p.APIKeyEnv != "" {
		key = "os.environ/" + p.APIKeyEnv
	}
	switch p.Type {
	case "bedrock":
		return litellmParams{Model: "bedrock/" + m.UpstreamID, AWSRegionName: p.Region}, nil
	case "openai":
		return litellmParams{Model: "openai/" + m.UpstreamID, APIKey: key}, nil
	case "anthropic":
		return litellmParams{Model: "anthropic/" + m.UpstreamID, APIKey: key}, nil
	case "azure":
		return litellmParams{Model: "azure/" + m.UpstreamID, APIBase: p.Endpoint, APIKey: key}, nil
	case "vertex":
		return litellmParams{Model: "vertex_ai/" + m.UpstreamID, VertexProject: "os.environ/GOOGLE_CLOUD_PROJECT", VertexLoc: p.Region}, nil
	case "openai-compatible":
		return litellmParams{Model: "openai/" + m.UpstreamID, APIBase: strings.TrimSuffix(p.Endpoint, "/"), APIKey: key}, nil
	}
	return litellmParams{}, fmt.Errorf("provider %s: unsupported type %q", p.Name, p.Type)
}
