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

// Package policy evaluates authorization with an embedded OPA engine.
//
// The Rego bundle in rego/ is compiled into the binary. Its data document is
// built from the estate plus live registry state, and rebuilt whenever either
// changes. Operators can add rules in package chautari.custom; any message
// they put in `deny` refuses the request.
package policy

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/lukelittle/chautari/internal/estate"
)

//go:embed rego/authz.rego
var bundle embed.FS

// Actions understood by the policy.
const (
	ActionModel = "model.invoke"
	ActionTool  = "tool.call"
	ActionAgent = "agent.call"
)

// Input is one access request.
type Input struct {
	Subject   Subject  `json:"subject"`
	Action    string   `json:"action"`
	Resource  Resource `json:"resource"`
	DataClass string   `json:"data_class"`
}

// Subject is who is asking.
type Subject struct {
	Team string `json:"team"`
	App  string `json:"app,omitempty"`
	Key  string `json:"key,omitempty"`
}

// Resource is what they are asking for. Tool is the MCP tool name within a
// tool server, for tool.call.
type Resource struct {
	Name string `json:"name"`
	Tool string `json:"tool,omitempty"`
}

// Decision is the policy's answer.
type Decision struct {
	Allow   bool     `json:"allow"`
	Reasons []string `json:"reasons"`
}

// Status reports an entry's lifecycle status by kind and name.
type Status func(kind, name string) string

// Engine evaluates decisions. It is safe for concurrent use.
type Engine struct {
	mu      sync.RWMutex
	query   rego.PreparedEvalQuery
	modules map[string]string
}

// Files returns the embedded Rego bundle, for the generator to write out.
func Files() map[string][]byte {
	out := map[string][]byte{}
	fs.WalkDir(bundle, "rego", func(p string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err == nil && !d.IsDir() {
			b, _ := bundle.ReadFile(p)
			out[filepath.Base(p)] = b
		}
		return nil
	})
	return out
}

// New compiles the bundle plus any *.rego files in policyDir (may be "").
func New(policyDir string) (*Engine, error) {
	modules := map[string]string{}
	for name, b := range Files() {
		modules["chautari/"+name] = string(b)
	}
	if policyDir != "" {
		entries, err := os.ReadDir(policyDir)
		if err != nil {
			return nil, fmt.Errorf("policy dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") || strings.HasSuffix(e.Name(), "_test.rego") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(policyDir, e.Name()))
			if err != nil {
				return nil, err
			}
			modules["custom/"+e.Name()] = string(b)
		}
	}
	eng := &Engine{modules: modules}
	if err := eng.Load(&estate.Estate{}, nil); err != nil {
		return nil, err
	}
	return eng, nil
}

// Load replaces the data document. status may be nil to use CDL flags.
func (e *Engine) Load(est *estate.Estate, status Status) error {
	store := inmem.NewFromObject(map[string]any{"estate": Data(est, status)})
	opts := []func(*rego.Rego){
		rego.Query("data.chautari.authz.decision"),
		rego.Store(store),
	}
	names := make([]string, 0, len(e.modules))
	for n := range e.modules {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		opts = append(opts, rego.Module(n, e.modules[n]))
	}
	q, err := rego.New(opts...).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	e.mu.Lock()
	e.query = q
	e.mu.Unlock()
	return nil
}

// Decide evaluates one request. Any evaluation failure is a deny: we fail
// closed.
func (e *Engine) Decide(ctx context.Context, in Input) Decision {
	e.mu.RLock()
	q := e.query
	e.mu.RUnlock()
	rs, err := q.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{Reasons: []string{"policy evaluation failed: " + err.Error()}}
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Decision{Reasons: []string{"policy produced no decision"}}
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{Reasons: []string{"policy produced a malformed decision"}}
	}
	d := Decision{Reasons: []string{}}
	d.Allow, _ = m["allow"].(bool)
	if rs, ok := m["reasons"].([]any); ok {
		for _, r := range rs {
			d.Reasons = append(d.Reasons, fmt.Sprint(r))
		}
	}
	if !d.Allow && len(d.Reasons) == 0 {
		d.Reasons = []string{"denied"}
	}
	return d
}

// Data builds the policy data document from an estate and live statuses.
func Data(e *estate.Estate, status Status) map[string]any {
	st := func(kind, name string, approved bool) string {
		if status != nil {
			if s := status(kind, name); s != "" {
				return s
			}
			return "unregistered"
		}
		if approved {
			return "approved"
		}
		return "requested"
	}
	teams := map[string]any{}
	for _, t := range e.Teams {
		teams[t.Name] = map[string]any{
			"name": t.Name, "models": strs(t.Models), "tools": strs(t.Tools), "clearance": string(t.Clearance),
		}
	}
	models := map[string]any{}
	for _, m := range e.Models {
		models[m.Name] = map[string]any{
			"name": m.Name, "status": st("model", m.Name, m.Approved), "data_class": string(m.DataClass),
			"provider": m.Provider, "risk_tier": m.RiskTier,
		}
	}
	tools := map[string]any{}
	for _, t := range e.Tools {
		tools[t.Name] = map[string]any{
			"name": t.Name, "status": st("tool", t.Name, t.Approved), "data_class": string(t.DataClass),
			"allow": strs(t.Allow), "scope": t.Scope, "owners": strs(t.Owners),
		}
	}
	agents := map[string]any{}
	for _, a := range e.Agents {
		agents[a.Name] = map[string]any{
			"name": a.Name, "status": st("agent", a.Name, a.Approved), "team": a.Team,
		}
	}
	return map[string]any{"teams": teams, "models": models, "tools": tools, "agents": agents}
}

func strs(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
