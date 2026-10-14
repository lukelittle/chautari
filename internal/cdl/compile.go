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

package cdl

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/lukelittle/chautari/internal/estate"
)

// LoadFile reads, parses and compiles a CDL file.
func LoadFile(path string) (*estate.Estate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Compile(filepath.Base(path), string(b))
}

// Compile parses and compiles CDL source into a validated estate.
func Compile(file, src string) (*estate.Estate, error) {
	f, perr := Parse(file, src)
	if perr != nil {
		return nil, perr
	}
	c := &compiler{file: file, errs: &ErrorList{}}
	e := c.compile(f)
	sum := sha256.Sum256([]byte(src))
	e.Source = estate.Source{File: file, SHA256: hex.EncodeToString(sum[:])}
	if err := c.errs.err(); err != nil {
		return nil, err
	}
	e.Sort()
	return e, nil
}

// Detectors are the guardrail detector names CDL accepts.
var Detectors = []string{"ssn", "card", "email", "phone", "iban", "aws-key", "pii", "injection", "topic", "bedrock"}

// PIIDetectors are what `pii` (or a directive with no detectors) expands to.
var PIIDetectors = []string{"ssn", "card", "email", "phone", "iban", "aws-key"}

var providerTypes = []string{"bedrock", "openai", "anthropic", "azure", "vertex", "openai-compatible"}

type compiler struct {
	file string
	errs *ErrorList
	// declared names per kind, with positions, for reference checks
	names map[string]map[string]Pos
}

func (c *compiler) errorf(p Pos, hint, format string, args ...any) {
	c.errs.add(c.file, p, fmt.Sprintf(format, args...), hint)
}

func (c *compiler) compile(f *File) *estate.Estate {
	e := &estate.Estate{
		Dataplane:        "agentgateway",
		Region:           "us-east-1",
		Environment:      "dev",
		DefaultDataClass: estate.Internal,
	}
	c.names = map[string]map[string]Pos{}
	for _, k := range Kinds {
		c.names[k] = map[string]Pos{}
	}
	estateSeen := false
	for _, d := range f.Decls {
		if prev, dup := c.names[d.Kind][d.Name]; dup {
			c.errorf(d.Pos, fmt.Sprintf("first declared at %s", prev), "%s %q is declared twice", d.Kind, d.Name)
			continue
		}
		c.names[d.Kind][d.Name] = d.Pos
		if len(d.Name) > MaxNameLen {
			c.errorf(d.Pos, "names become Kubernetes and gateway resource names", "%s name %q is longer than %d characters", d.Kind, d.Name, MaxNameLen)
		}
		if d.Kind == "estate" {
			if estateSeen {
				c.errorf(d.Pos, "a file describes one estate", "only one estate declaration is allowed")
			}
			estateSeen = true
		}
	}

	for _, d := range f.Decls {
		props := c.props(d)
		switch d.Kind {
		case "estate":
			c.estate(e, d, props)
		case "provider":
			e.Providers = append(e.Providers, c.provider(d, props))
		case "model":
			e.Models = append(e.Models, c.model(d, props))
		case "tool":
			e.Tools = append(e.Tools, c.tool(d, props))
		case "agent":
			e.Agents = append(e.Agents, c.agent(d, props))
		case "team":
			e.Teams = append(e.Teams, c.team(d, props))
		case "app":
			e.Apps = append(e.Apps, c.app(d, props))
		case "policy":
			e.Policies = append(e.Policies, c.policy(d, props))
		}
	}
	if e.Name == "" {
		e.Name = "estate"
	}
	if e.Org == "" {
		e.Org = e.Name
	}
	c.crossChecks(e, f)
	return e
}

// props indexes a declaration's properties by key, reporting unknown and
// duplicate keys and invalid strings. A repeatable key maps to its first
// occurrence; use all to read every occurrence.
func (c *compiler) props(d *Decl) map[string]*Prop {
	out := map[string]*Prop{}
	for _, p := range d.Props {
		if !isKey(d.Kind, p.Key) {
			c.errorf(p.Pos, suggest(p.Key, keys[d.Kind]), "unknown property %q for %s", p.Key, d.Kind)
			continue
		}
		c.checkStrings(d, p, p.Values)
		if prev, dup := out[p.Key]; dup && !repeatable(d.Kind, p.Key) {
			c.errorf(p.Pos, fmt.Sprintf("first set at %s", prev.Pos), "property %q is set twice in %s %s", p.Key, d.Kind, d.Name)
			continue
		} else if dup {
			continue
		}
		out[p.Key] = p
	}
	return out
}

// all returns every occurrence of a repeatable key, in source order. Each
// occurrence is read on its own: `block outbound ssn, block card` is two
// directives, and the second is missing its direction.
func all(d *Decl, key string) []*Prop {
	var out []*Prop
	for _, p := range d.Props {
		if p.Key == key {
			out = append(out, p)
		}
	}
	return out
}

// checkStrings rejects string values that would be unsafe in the generated
// stack. Strings are copied into YAML, Helm templates (which evaluate {{ }}
// even in NOTES.txt), Go templates and agentgateway's config, which expands
// ${VAR}. Control characters, including newlines and tabs, could break out
// of a YAML scalar.
func (c *compiler) checkStrings(d *Decl, p *Prop, vals []Value) {
	for _, v := range vals {
		if v.Kind == VList {
			c.checkStrings(d, p, v.Items)
			continue
		}
		if v.Kind != VString {
			continue
		}
		for _, r := range v.Text {
			if unicode.IsControl(r) {
				c.errorf(v.Pos, "strings are copied into generated YAML and config; keep them on one line without tabs",
					"%s.%s: string %q contains control character %U", d.Name, p.Key, v.Text, r)
				break
			}
		}
		for _, seq := range []string{"{{", "}}", "[[", "]]", "${"} {
			if strings.Contains(v.Text, seq) {
				c.errorf(v.Pos, "strings are copied into generated templates and gateway config, where it would be expanded",
					"%s.%s: string %q contains %q", d.Name, p.Key, v.Text, seq)
				break
			}
		}
	}
}

func repeatable(kind, key string) bool {
	return kind == "team" && key == "rate" || kind == "app" && key == "rate" ||
		kind == "policy" && (key == "redact" || key == "block" || key == "flag")
}

// ── value helpers ───────────────────────────────────────────────────────────

func (c *compiler) single(d *Decl, p *Prop) (Value, bool) {
	if p == nil {
		return Value{}, false
	}
	if len(p.Values) != 1 {
		c.errorf(p.Pos, "", "%s.%s takes a single value, got %d", d.Name, p.Key, len(p.Values))
		return Value{}, false
	}
	return p.Values[0], true
}

func (c *compiler) word(d *Decl, p *Prop) string {
	v, ok := c.single(d, p)
	if !ok {
		return ""
	}
	if v.Kind != VIdent && v.Kind != VString {
		c.errorf(v.Pos, "", "%s.%s expects a name or string, got %s", d.Name, p.Key, v.Kind)
		return ""
	}
	return v.Text
}

func (c *compiler) str(d *Decl, p *Prop) string {
	v, ok := c.single(d, p)
	if !ok {
		return ""
	}
	if v.Kind != VString {
		c.errorf(v.Pos, fmt.Sprintf("write %s %q", p.Key, v.String()), "%s.%s expects a quoted string", d.Name, p.Key)
		return v.Text
	}
	return v.Text
}

func (c *compiler) enum(d *Decl, p *Prop, allowed []string) string {
	v, ok := c.single(d, p)
	if !ok {
		return ""
	}
	for _, a := range allowed {
		if v.Text == a && (v.Kind == VIdent || v.Kind == VString) {
			return a
		}
	}
	c.errorf(v.Pos, suggest(v.Text, allowed), "invalid %s %s for %s", p.Key, v.String(), d.Name)
	return ""
}

func (c *compiler) boolean(d *Decl, p *Prop) bool {
	return c.enum(d, p, []string{"true", "false"}) == "true"
}

func (c *compiler) dataClass(d *Decl, p *Prop) estate.DataClass {
	names := make([]string, len(estate.DataClasses))
	for i, dc := range estate.DataClasses {
		names[i] = string(dc)
	}
	return estate.DataClass(c.enum(d, p, names))
}

// list accepts either a bracketed list or bare values (`owners a, b`).
func (c *compiler) list(d *Decl, p *Prop) []Value {
	if p == nil {
		return nil
	}
	var out []Value
	for _, v := range p.Values {
		if v.Kind == VList {
			out = append(out, v.Items...)
		} else {
			out = append(out, v)
		}
	}
	return out
}

func (c *compiler) idents(d *Decl, p *Prop) []string {
	var out []string
	for _, v := range c.list(d, p) {
		if v.Kind != VIdent && v.Kind != VString {
			c.errorf(v.Pos, "", "%s.%s expects names, got %s", d.Name, p.Key, v.Kind)
			continue
		}
		out = append(out, v.Text)
	}
	return out
}

func (c *compiler) refs(d *Decl, p *Prop, kind string) []string {
	if p == nil {
		return []string{}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, v := range c.list(d, p) {
		if v.Kind != VIdent && v.Kind != VString {
			c.errorf(v.Pos, "", "%s.%s expects %s names, got %s", d.Name, p.Key, kind, v.Kind)
			continue
		}
		if c.ref(d, v, kind, p.Key) && !seen[v.Text] {
			seen[v.Text] = true
			out = append(out, v.Text)
		}
	}
	return out
}

func (c *compiler) ref(d *Decl, v Value, kind, key string) bool {
	if _, ok := c.names[kind][v.Text]; ok {
		return true
	}
	var cands []string
	for n := range c.names[kind] {
		cands = append(cands, n)
	}
	sort.Strings(cands)
	c.errorf(v.Pos, suggest(v.Text, cands), "%s %q references unknown %s %q", d.Kind, d.Name, kind, v.Text)
	return false
}

func (c *compiler) singleRef(d *Decl, p *Prop, kind string) string {
	v, ok := c.single(d, p)
	if !ok {
		return ""
	}
	if c.ref(d, v, kind, p.Key) {
		return v.Text
	}
	return ""
}

func (c *compiler) budget(d *Decl, p *Prop) *estate.Budget {
	v, ok := c.single(d, p)
	if !ok {
		return nil
	}
	periods := []string{"day", "week", "month"}
	if v.Kind != VQuantity || v.Unit != "usd" {
		c.errorf(v.Pos, "write it like 2000 usd/month", "%s.%s expects a spend quantity", d.Name, p.Key)
		return nil
	}
	for _, per := range periods {
		if v.Per == per {
			if v.Num <= 0 {
				c.errorf(v.Pos, "", "%s.%s must be positive", d.Name, p.Key)
			}
			return &estate.Budget{USD: v.Num, Period: estate.Period(per)}
		}
	}
	c.errorf(v.Pos, suggest(v.Per, periods), "budget period %q is not supported", v.Per)
	return nil
}

func (c *compiler) rates(d *Decl, props []*Prop) []estate.Rate {
	out := []estate.Rate{}
	seen := map[string]Pos{}
	for _, p := range props {
		for _, v := range c.list(d, p) {
			if r, ok := c.rate(d, p, v); ok {
				k := string(r.Unit) + "/" + string(r.Period)
				if prev, dup := seen[k]; dup {
					c.errorf(v.Pos, fmt.Sprintf("first set at %s", prev), "two %s limits on %s %s; keep one", k, d.Kind, d.Name)
					continue
				}
				seen[k] = v.Pos
				out = append(out, r)
			}
		}
	}
	return out
}

func (c *compiler) rate(d *Decl, p *Prop, v Value) (estate.Rate, bool) {
	if v.Kind != VQuantity || (v.Unit != "tokens" && v.Unit != "requests") {
		c.errorf(v.Pos, "write it like 20k tokens/min or 100 requests/min", "%s.%s expects a rate", d.Name, p.Key)
		return estate.Rate{}, false
	}
	if v.Per != "min" && v.Per != "hour" {
		c.errorf(v.Pos, suggest(v.Per, []string{"min", "hour"}), "rate period %q is not supported", v.Per)
		return estate.Rate{}, false
	}
	if v.Num < 1 {
		c.errorf(v.Pos, "", "%s.%s must be at least 1", d.Name, p.Key)
		return estate.Rate{}, false
	}
	if v.Num != math.Trunc(v.Num) {
		c.errorf(v.Pos, "rate limits count whole tokens or requests", "%s.%s must be a whole number, got %s", d.Name, p.Key, v.String())
		return estate.Rate{}, false
	}
	if v.Num > maxRate {
		c.errorf(v.Pos, "", "%s.%s is too large", d.Name, p.Key)
		return estate.Rate{}, false
	}
	return estate.Rate{Limit: int64(v.Num), Unit: estate.RateUnit(v.Unit), Period: estate.Period(v.Per)}, true
}

// maxRate keeps a limit exactly representable as both float64 and int64.
const maxRate = 1 << 53

func (c *compiler) price(d *Decl, p *Prop) float64 {
	v, ok := c.single(d, p)
	if !ok {
		return 0
	}
	if v.Kind == VQuantity && v.Unit == "usd" && v.Per == "mtok" && v.Num >= 0 {
		return v.Num
	}
	c.errorf(v.Pos, "write it like 3 usd/mtok (USD per million tokens)", "%s.%s expects a price", d.Name, p.Key)
	return 0
}

// ── declarations ────────────────────────────────────────────────────────────

func (c *compiler) estate(e *estate.Estate, d *Decl, p map[string]*Prop) {
	e.Name = d.Name
	if v := p["org"]; v != nil {
		e.Org = c.str(d, v)
	}
	if v := p["dataplane"]; v != nil {
		e.Dataplane = c.enum(d, v, []string{"agentgateway", "litellm"})
	}
	if v := p["region"]; v != nil {
		e.Region = c.word(d, v)
	}
	if v := p["environment"]; v != nil {
		e.Environment = c.word(d, v)
	}
	if v := p["default-data-class"]; v != nil {
		e.DefaultDataClass = c.dataClass(d, v)
	}
}

func (c *compiler) provider(d *Decl, p map[string]*Prop) estate.Provider {
	pr := estate.Provider{Name: d.Name}
	if v := p["type"]; v != nil {
		pr.Type = c.enum(d, v, providerTypes)
	} else {
		c.errorf(d.Pos, suggest("", providerTypes), "provider %q needs a type", d.Name)
	}
	if v := p["region"]; v != nil {
		pr.Region = c.word(d, v)
	}
	if v := p["endpoint"]; v != nil {
		pr.Endpoint = c.str(d, v)
		if !strings.HasPrefix(pr.Endpoint, "http://") && !strings.HasPrefix(pr.Endpoint, "https://") {
			c.errorf(v.Pos, "", "provider endpoint must be an http(s) URL")
		}
	}
	if pr.Type == "openai-compatible" && pr.Endpoint == "" {
		c.errorf(d.Pos, `add endpoint "https://…"`, "provider %q of type openai-compatible needs an endpoint", d.Name)
	}
	if pr.Type == "azure" {
		if pr.Endpoint == "" {
			c.errorf(d.Pos, `add endpoint "https://<resource>.openai.azure.com"`, "provider %q of type azure needs an endpoint", d.Name)
		} else if u, err := url.Parse(pr.Endpoint); err != nil || u.Scheme != "https" || u.Hostname() == "" {
			c.errorf(p["endpoint"].Pos, `write it like "https://<resource>.openai.azure.com"`, "provider %q of type azure needs an https endpoint", d.Name)
		}
	}
	if pr.Type == "bedrock" && pr.Region == "" {
		pr.Region = "us-east-1"
	}
	if v := p["api-key-env"]; v != nil {
		pr.APIKeyEnv = c.word(d, v)
		// The gateway config interpolates it as ${NAME}.
		if pr.APIKeyEnv != "" && !reEnvName.MatchString(pr.APIKeyEnv) {
			c.errorf(v.Pos, "use upper-case letters, digits and _, like OPENAI_API_KEY",
				"provider %q api-key-env %q is not a valid environment variable name", d.Name, pr.APIKeyEnv)
		}
	} else if pr.Type != "bedrock" && pr.Type != "vertex" {
		pr.APIKeyEnv = envName(d.Name) + "_API_KEY"
	}
	return pr
}

var reEnvName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func envName(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(s))
}

func (c *compiler) model(d *Decl, p map[string]*Prop) estate.Model {
	m := estate.Model{Name: d.Name, UpstreamID: d.Name, DataClass: estate.Internal, RiskTier: "medium"}
	if v := p["provider"]; v != nil {
		m.Provider = c.singleRef(d, v, "provider")
	} else {
		c.errorf(d.Pos, "add provider <name>", "model %q needs a provider", d.Name)
	}
	if v := p["id"]; v != nil {
		m.UpstreamID = c.word(d, v)
	}
	if v := p["approved"]; v != nil {
		m.Approved = c.boolean(d, v)
	}
	if v := p["data-class"]; v != nil {
		m.DataClass = c.dataClass(d, v)
	}
	if v := p["cost-in"]; v != nil {
		m.CostInUSD = c.price(d, v)
	}
	if v := p["cost-out"]; v != nil {
		m.CostOutUSD = c.price(d, v)
	}
	if v := p["risk-tier"]; v != nil {
		m.RiskTier = c.enum(d, v, []string{"low", "medium", "high"})
	}
	if v := p["owner"]; v != nil {
		m.Owner = c.singleRef(d, v, "team")
	}
	if v := p["description"]; v != nil {
		m.Description = c.str(d, v)
	}
	return m
}

func (c *compiler) tool(d *Decl, p map[string]*Prop) estate.Tool {
	t := estate.Tool{Name: d.Name, Scope: "read", DataClass: estate.Internal, Owners: []string{}, Allow: []string{}}
	if strings.Contains(d.Name, "_") {
		// agentgateway multiplexes MCP targets as <target>_<tool> and splits
		// at the first '_', so the target name itself must not contain one.
		c.errorf(d.Pos, fmt.Sprintf("use '-' instead, like %s", strings.ReplaceAll(d.Name, "_", "-")),
			"tool name %q contains '_', which the gateway uses to join tool server and tool names", d.Name)
	}
	if v := p["endpoint"]; v != nil {
		t.Endpoint = c.str(d, v)
	} else {
		c.errorf(d.Pos, `add endpoint "http://host:port/mcp"`, "tool %q needs an endpoint", d.Name)
	}
	if v := p["scope"]; v != nil {
		t.Scope = c.enum(d, v, []string{"read", "write", "admin"})
	}
	if v := p["owners"]; v != nil {
		t.Owners = c.refs(d, v, "team")
	}
	if v := p["allow"]; v != nil {
		t.Allow = c.idents(d, v)
		if len(c.list(d, v)) == 0 {
			c.errorf(v.Pos, "omit allow to expose every tool", "tool %q has an empty allow list, which would expose every tool", d.Name)
		}
	}
	if t.Allow == nil {
		t.Allow = []string{}
	}
	if v := p["approved"]; v != nil {
		t.Approved = c.boolean(d, v)
	}
	if v := p["data-class"]; v != nil {
		t.DataClass = c.dataClass(d, v)
	}
	if v := p["description"]; v != nil {
		t.Description = c.str(d, v)
	}
	return t
}

func (c *compiler) agent(d *Decl, p map[string]*Prop) estate.Agent {
	a := estate.Agent{Name: d.Name, Tools: []string{}}
	if v := p["team"]; v != nil {
		a.Team = c.singleRef(d, v, "team")
	} else {
		c.errorf(d.Pos, "add team <name>", "agent %q needs a team", d.Name)
	}
	if v := p["model"]; v != nil {
		a.Model = c.singleRef(d, v, "model")
	}
	if v := p["tools"]; v != nil {
		a.Tools = c.refs(d, v, "tool")
	}
	if v := p["endpoint"]; v != nil {
		a.Endpoint = c.str(d, v)
		if a.Endpoint != "" && !validAgentEndpoint(a.Endpoint) {
			c.errorf(v.Pos, `write it like "host:8080" or "https://host/a2a"`,
				"agent %q endpoint %q must be host:port or an http(s) URL without query or fragment", d.Name, a.Endpoint)
		}
	}
	if v := p["approved"]; v != nil {
		a.Approved = c.boolean(d, v)
	}
	if v := p["description"]; v != nil {
		a.Description = c.str(d, v)
	}
	return a
}

func (c *compiler) team(d *Decl, p map[string]*Prop) estate.Team {
	t := estate.Team{Name: d.Name, Clearance: estate.Internal, Models: []string{}, Tools: []string{}}
	t.Models = c.refs(d, p["models"], "model")
	t.Tools = c.refs(d, p["tools"], "tool")
	if v := p["budget"]; v != nil {
		t.Budget = c.budget(d, v)
	}
	t.Rates = c.rates(d, all(d, "rate"))
	if v := p["clearance"]; v != nil {
		t.Clearance = c.dataClass(d, v)
	}
	if v := p["owner"]; v != nil {
		t.Owner = c.str(d, v)
	}
	return t
}

func (c *compiler) app(d *Decl, p map[string]*Prop) estate.App {
	a := estate.App{Name: d.Name}
	if v := p["team"]; v != nil {
		a.Team = c.singleRef(d, v, "team")
	} else {
		c.errorf(d.Pos, "add team <name>", "app %q needs a team", d.Name)
	}
	if v := p["budget"]; v != nil {
		a.Budget = c.budget(d, v)
	}
	a.Rates = c.rates(d, all(d, "rate"))
	if v := p["key-budget"]; v != nil {
		a.KeyBudget = c.budget(d, v)
	}
	if v := p["data-class"]; v != nil {
		a.DataClass = c.dataClass(d, v)
	}
	if v := p["description"]; v != nil {
		a.Description = c.str(d, v)
	}
	return a
}

func (c *compiler) policy(d *Decl, p map[string]*Prop) estate.Policy {
	pol := estate.Policy{Name: d.Name, Topics: []string{}, AppliesTo: []string{}, Rules: []estate.Rule{}}
	for _, action := range []estate.Action{estate.Flag, estate.Redact, estate.Block} {
		for _, prop := range all(d, string(action)) {
			pol.Rules = append(pol.Rules, c.directive(d, prop, action)...)
		}
	}
	if v := p["topics"]; v != nil {
		items := c.list(d, v)
		if len(items) == 0 {
			c.errorf(v.Pos, "list at least one topic, or omit topics", "policy %q has an empty topics list", d.Name)
		}
		for _, t := range items {
			if t.Kind != VString && t.Kind != VIdent {
				c.errorf(t.Pos, "", "topics must be strings")
				continue
			}
			if strings.TrimSpace(t.Text) == "" {
				c.errorf(t.Pos, "remove it; a blank topic matches nothing", "policy %q has a blank topic", d.Name)
				continue
			}
			pol.Topics = append(pol.Topics, t.Text)
		}
	}
	if v := p["applies-to"]; v != nil {
		pol.AppliesTo = c.refs(d, v, "team")
		if len(c.list(d, v)) == 0 {
			c.errorf(v.Pos, "omit applies-to to apply the policy to every team", "policy %q has an empty applies-to list, which would apply it to every team", d.Name)
		}
	}
	if v := p["bedrock-guardrail"]; v != nil {
		pol.BedrockGuardrail = c.word(d, v)
		pol.BedrockVersion = "DRAFT"
	}
	if v := p["bedrock-version"]; v != nil {
		pol.BedrockVersion = c.word(d, v)
	}
	if v := p["description"]; v != nil {
		pol.Description = c.str(d, v)
	}
	if len(pol.Rules) == 0 {
		c.errorf(d.Pos, "add redact, block or flag", "policy %q has no rules", d.Name)
	}
	uses := func(det string) bool {
		for _, r := range pol.Rules {
			for _, x := range r.Detectors {
				if x == det {
					return true
				}
			}
		}
		return false
	}
	if uses("topic") && len(pol.Topics) == 0 {
		c.errorf(d.Pos, `add topics ["…"]`, "policy %q uses the topic detector but lists no topics", d.Name)
	}
	if uses("bedrock") && pol.BedrockGuardrail == "" {
		c.errorf(d.Pos, `add bedrock-guardrail "<id>"`, "policy %q uses the bedrock detector but names no guardrail", d.Name)
	}
	if pol.BedrockGuardrail != "" && !uses("bedrock") {
		// Naming a guardrail implies using it: block both directions by default.
		pol.Rules = append(pol.Rules,
			estate.Rule{Action: estate.Block, Direction: estate.Inbound, Detectors: []string{"bedrock"}},
			estate.Rule{Action: estate.Block, Direction: estate.Outbound, Detectors: []string{"bedrock"}})
	}
	sort.SliceStable(pol.Rules, func(i, j int) bool {
		if pol.Rules[i].Direction != pol.Rules[j].Direction {
			return pol.Rules[i].Direction < pol.Rules[j].Direction
		}
		return pol.Rules[i].Action.Strength() > pol.Rules[j].Action.Strength()
	})
	return pol
}

// directive parses `<action> <direction> [detectors...]`.
func (c *compiler) directive(d *Decl, p *Prop, action estate.Action) []estate.Rule {
	vals := c.list(d, p)
	// One directive may name several directions (`block inbound ssn outbound
	// card`), so split on direction words.
	var rules []estate.Rule
	var cur []estate.Direction
	var dets []string
	flush := func(pos Pos) {
		if cur == nil {
			return
		}
		if len(dets) == 0 {
			dets = append([]string(nil), PIIDetectors...)
		}
		for _, dir := range cur {
			rules = append(rules, estate.Rule{Action: action, Direction: dir, Detectors: dets})
		}
		cur, dets = nil, nil
	}
	for _, v := range vals {
		if v.Kind != VIdent {
			c.errorf(v.Pos, "", "%s.%s expects a direction and detector names, got %s", d.Name, p.Key, v.String())
			continue
		}
		switch v.Text {
		case "inbound":
			flush(v.Pos)
			cur = []estate.Direction{estate.Inbound}
			continue
		case "outbound":
			flush(v.Pos)
			cur = []estate.Direction{estate.Outbound}
			continue
		case "both":
			flush(v.Pos)
			cur = []estate.Direction{estate.Inbound, estate.Outbound}
			continue
		}
		if cur == nil {
			c.errorf(v.Pos, "start with inbound, outbound or both", "%s.%s is missing a direction", d.Name, p.Key)
			cur = []estate.Direction{estate.Inbound}
		}
		known := false
		for _, det := range Detectors {
			if det == v.Text {
				known = true
			}
		}
		if !known {
			c.errorf(v.Pos, suggest(v.Text, Detectors), "unknown detector %q", v.Text)
			continue
		}
		if v.Text == "pii" {
			dets = append(dets, PIIDetectors...)
		} else {
			dets = append(dets, v.Text)
		}
	}
	if len(vals) > 0 {
		flush(vals[len(vals)-1].Pos)
	}
	for i := range rules {
		rules[i].Detectors = dedupe(rules[i].Detectors)
	}
	return rules
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// crossChecks validates relationships that span declarations.
func (c *compiler) crossChecks(e *estate.Estate, f *File) {
	pos := func(kind, name string) Pos { return c.names[kind][name] }
	teams := map[string]estate.Team{}
	for _, t := range e.Teams {
		teams[t.Name] = t
	}
	for _, a := range e.Agents {
		t, ok := teams[a.Team]
		if !ok {
			continue
		}
		if a.Model != "" && !contains(t.Models, a.Model) {
			c.errorf(pos("agent", a.Name), fmt.Sprintf("add %s to team %s's models", a.Model, t.Name),
				"agent %q uses model %q, which team %q is not entitled to", a.Name, a.Model, t.Name)
		}
		for _, tool := range a.Tools {
			if !contains(t.Tools, tool) {
				c.errorf(pos("agent", a.Name), fmt.Sprintf("add %s to team %s's tools", tool, t.Name),
					"agent %q uses tool %q, which team %q is not entitled to", a.Name, tool, t.Name)
			}
		}
	}
	for _, a := range e.Apps {
		t, ok := teams[a.Team]
		if !ok {
			continue
		}
		if a.DataClass != "" && a.DataClass.Rank() > t.Clearance.Rank() {
			c.errorf(pos("app", a.Name), "", "app %q defaults to data class %s, above team %q's clearance (%s)",
				a.Name, a.DataClass, t.Name, t.Clearance)
		}
	}
	if len(e.Teams) == 0 && len(f.Decls) > 0 {
		c.errorf(Pos{1, 1}, "add a team block so someone can use the estate", "the estate declares no teams")
	}
}

// validAgentEndpoint accepts host:port or an http(s) URL with an optional
// port and path. The gateway renderer defaults the port from the scheme,
// carries the path with a URL rewrite and turns on backend TLS for https; it
// has nowhere to put a query string, fragment or credentials.
func validAgentEndpoint(s string) bool {
	if strings.ContainsAny(s, " ?#") {
		return false
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil {
			return false
		}
		if strings.HasSuffix(u.Host, ":") || !validHost(u.Hostname()) {
			return false
		}
		return u.Port() == "" || validPort(u.Port())
	}
	host, port, err := net.SplitHostPort(s)
	return err == nil && validHost(host) && validPort(port)
}

var reHostname = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

func validHost(h string) bool { return net.ParseIP(h) != nil || reHostname.MatchString(h) }

func validPort(p string) bool {
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
