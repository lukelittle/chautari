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

// Package estate is the compiled, validated model of an organisation's AI
// estate. Every other package consumes an *Estate; only package cdl builds one.
//
// All slices are sorted by name so that anything rendered from an Estate is
// deterministic, which is what makes `chautari generate` idempotent.
package estate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// DataClass is an ordered sensitivity label.
type DataClass string

const (
	Public       DataClass = "public"
	Internal     DataClass = "internal"
	Confidential DataClass = "confidential"
	Restricted   DataClass = "restricted"
)

// DataClasses lists all classes from least to most sensitive.
var DataClasses = []DataClass{Public, Internal, Confidential, Restricted}

// Rank returns the ordinal of a data class, or -1 if unknown.
func (d DataClass) Rank() int {
	for i, c := range DataClasses {
		if c == d {
			return i
		}
	}
	return -1
}

// Valid reports whether d is a known data class.
func (d DataClass) Valid() bool { return d.Rank() >= 0 }

// Period is a calendar window for spend budgets or a window for rate limits.
type Period string

const (
	Minute Period = "min"
	Hour   Period = "hour"
	Day    Period = "day"
	Week   Period = "week"
	Month  Period = "month"
)

// Budget is a spend ceiling in USD over a calendar period.
type Budget struct {
	USD    float64 `json:"usd"`
	Period Period  `json:"period"`
}

// RateUnit is what a rate limit counts.
type RateUnit string

const (
	Tokens   RateUnit = "tokens"
	Requests RateUnit = "requests"
)

// Rate is a limit on tokens or requests per window.
type Rate struct {
	Limit  int64    `json:"limit"`
	Unit   RateUnit `json:"unit"`
	Period Period   `json:"period"`
}

func (r Rate) String() string { return fmt.Sprintf("%d %s/%s", r.Limit, r.Unit, r.Period) }

// Estate is the whole compiled CDL file.
type Estate struct {
	Name             string     `json:"name"`
	Org              string     `json:"org"`
	Dataplane        string     `json:"dataplane"`
	Region           string     `json:"region"`
	Environment      string     `json:"environment"`
	DefaultDataClass DataClass  `json:"default_data_class"`
	Providers        []Provider `json:"providers"`
	Models           []Model    `json:"models"`
	Tools            []Tool     `json:"tools"`
	Agents           []Agent    `json:"agents"`
	Teams            []Team     `json:"teams"`
	Apps             []App      `json:"apps"`
	Policies         []Policy   `json:"policies"`
	// Source identifies the CDL that produced this estate: file name and
	// SHA-256 of its bytes. Used as the audit actor for estate-as-code approvals.
	Source Source `json:"source"`
}

// Source identifies a CDL file by name and content hash.
type Source struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Actor renders the source as an audit actor, e.g. "cdl:estate.cdl@1a2b3c4d".
func (s Source) Actor() string {
	h := s.SHA256
	if len(h) > 12 {
		h = h[:12]
	}
	return "cdl:" + s.File + "@" + h
}

// Provider is an upstream LLM provider.
type Provider struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Region    string `json:"region,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	APIKeyEnv string `json:"api_key_env,omitempty"`
}

// Model is a model offered through the gateway.
type Model struct {
	Name        string    `json:"name"`
	Provider    string    `json:"provider"`
	UpstreamID  string    `json:"upstream_id"`
	Approved    bool      `json:"approved"`
	DataClass   DataClass `json:"data_class"`
	CostInUSD   float64   `json:"cost_in_usd_per_mtok"`
	CostOutUSD  float64   `json:"cost_out_usd_per_mtok"`
	RiskTier    string    `json:"risk_tier"`
	Owner       string    `json:"owner,omitempty"`
	Description string    `json:"description,omitempty"`
}

// Cost returns the USD cost of a call with the given token counts.
func (m Model) Cost(promptTokens, completionTokens int64) float64 {
	return (float64(promptTokens)*m.CostInUSD + float64(completionTokens)*m.CostOutUSD) / 1_000_000
}

// Tool is an MCP server.
type Tool struct {
	Name        string    `json:"name"`
	Endpoint    string    `json:"endpoint"`
	Scope       string    `json:"scope"`
	Owners      []string  `json:"owners"`
	Allow       []string  `json:"allow"`
	Approved    bool      `json:"approved"`
	DataClass   DataClass `json:"data_class"`
	Description string    `json:"description,omitempty"`
}

// Agent is an A2A agent.
type Agent struct {
	Name        string   `json:"name"`
	Team        string   `json:"team"`
	Model       string   `json:"model,omitempty"`
	Tools       []string `json:"tools"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Approved    bool     `json:"approved"`
	Description string   `json:"description,omitempty"`
}

// Team is a group of people and apps sharing entitlements and a budget.
type Team struct {
	Name      string    `json:"name"`
	Models    []string  `json:"models"`
	Tools     []string  `json:"tools"`
	Budget    *Budget   `json:"budget,omitempty"`
	Rates     []Rate    `json:"rates"`
	Clearance DataClass `json:"clearance"`
	Owner     string    `json:"owner,omitempty"`
}

// App is a client application that holds API keys.
type App struct {
	Name        string    `json:"name"`
	Team        string    `json:"team"`
	Budget      *Budget   `json:"budget,omitempty"`
	Rates       []Rate    `json:"rates"`
	KeyBudget   *Budget   `json:"key_budget,omitempty"`
	DataClass   DataClass `json:"data_class,omitempty"`
	Description string    `json:"description,omitempty"`
}

// Direction is where a guardrail applies.
type Direction string

const (
	Inbound  Direction = "inbound"
	Outbound Direction = "outbound"
)

// Action is what a guardrail does on a finding. Ordered by strength.
type Action string

const (
	Flag   Action = "flag"
	Redact Action = "redact"
	Block  Action = "block"
)

// Strength orders actions: block > redact > flag.
func (a Action) Strength() int {
	switch a {
	case Block:
		return 3
	case Redact:
		return 2
	case Flag:
		return 1
	}
	return 0
}

// Rule is one guardrail directive, normalised to a single direction.
type Rule struct {
	Action    Action    `json:"action"`
	Direction Direction `json:"direction"`
	Detectors []string  `json:"detectors"`
}

// Policy is a named set of guardrail rules.
type Policy struct {
	Name             string   `json:"name"`
	Rules            []Rule   `json:"rules"`
	Topics           []string `json:"topics"`
	AppliesTo        []string `json:"applies_to"`
	BedrockGuardrail string   `json:"bedrock_guardrail,omitempty"`
	BedrockVersion   string   `json:"bedrock_version,omitempty"`
	Description      string   `json:"description,omitempty"`
}

// AppliesToTeam reports whether the policy covers the named team.
func (p Policy) AppliesToTeam(team string) bool {
	if len(p.AppliesTo) == 0 {
		return true
	}
	for _, t := range p.AppliesTo {
		if t == team {
			return true
		}
	}
	return false
}

// Model returns the named model.
func (e *Estate) Model(name string) (Model, bool) {
	for _, m := range e.Models {
		if m.Name == name {
			return m, true
		}
	}
	return Model{}, false
}

// Tool returns the named tool.
func (e *Estate) Tool(name string) (Tool, bool) {
	for _, t := range e.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

// Team returns the named team.
func (e *Estate) Team(name string) (Team, bool) {
	for _, t := range e.Teams {
		if t.Name == name {
			return t, true
		}
	}
	return Team{}, false
}

// App returns the named app.
func (e *Estate) App(name string) (App, bool) {
	for _, a := range e.Apps {
		if a.Name == name {
			return a, true
		}
	}
	return App{}, false
}

// Provider returns the named provider.
func (e *Estate) Provider(name string) (Provider, bool) {
	for _, p := range e.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return Provider{}, false
}

// PoliciesFor returns the policies that apply to a team, in name order.
func (e *Estate) PoliciesFor(team string) []Policy {
	var out []Policy
	for _, p := range e.Policies {
		if p.AppliesToTeam(team) {
			out = append(out, p)
		}
	}
	return out
}

// Sort puts every collection in canonical order. The compiler calls it; it is
// exported so tests and builders can normalise hand-built estates.
func (e *Estate) Sort() {
	sort.Slice(e.Providers, func(i, j int) bool { return e.Providers[i].Name < e.Providers[j].Name })
	sort.Slice(e.Models, func(i, j int) bool { return e.Models[i].Name < e.Models[j].Name })
	sort.Slice(e.Tools, func(i, j int) bool { return e.Tools[i].Name < e.Tools[j].Name })
	sort.Slice(e.Agents, func(i, j int) bool { return e.Agents[i].Name < e.Agents[j].Name })
	sort.Slice(e.Teams, func(i, j int) bool { return e.Teams[i].Name < e.Teams[j].Name })
	sort.Slice(e.Apps, func(i, j int) bool { return e.Apps[i].Name < e.Apps[j].Name })
	sort.Slice(e.Policies, func(i, j int) bool { return e.Policies[i].Name < e.Policies[j].Name })
	for i := range e.Teams {
		sort.Strings(e.Teams[i].Models)
		sort.Strings(e.Teams[i].Tools)
	}
	for i := range e.Tools {
		sort.Strings(e.Tools[i].Owners)
		sort.Strings(e.Tools[i].Allow)
	}
	for i := range e.Agents {
		sort.Strings(e.Agents[i].Tools)
	}
	for i := range e.Policies {
		sort.Strings(e.Policies[i].AppliesTo)
	}
}

// JSON renders the estate as canonical, indented JSON.
func (e *Estate) JSON() []byte {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		panic(err) // the Estate type contains nothing unmarshalable
	}
	return append(b, '\n')
}

// Digest is a stable hash of the estate's content (excluding Source).
func (e *Estate) Digest() string {
	c := *e
	c.Source = Source{}
	sum := sha256.Sum256(c.JSON())
	return hex.EncodeToString(sum[:])
}
