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

package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/estate"
)

func engine(t *testing.T, dir string) (*Engine, *estate.Estate) {
	t.Helper()
	e, err := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Load(e, nil); err != nil {
		t.Fatal(err)
	}
	return eng, e
}

func model(team, name, dc string) Input {
	return Input{Subject: Subject{Team: team, App: "app"}, Action: ActionModel, Resource: Resource{Name: name}, DataClass: dc}
}

func TestModelDecisions(t *testing.T) {
	eng, _ := engine(t, "")
	ctx := context.Background()
	cases := []struct {
		name   string
		in     Input
		allow  bool
		reason string
	}{
		{"entitled, approved, in class", model("lending", "claude-sonnet", "confidential"), true, ""},
		{"public data always fits", model("wealth", "gpt-4o", "public"), true, ""},
		{"not entitled", model("wealth", "claude-sonnet", "internal"), false, `team "wealth" is not entitled to model "claude-sonnet"`},
		{"not approved", model("lending", "llama-70b", "public"), false, `model "llama-70b" is requested, not approved`},
		{"unknown model", model("lending", "gpt-9", "internal"), false, `model "gpt-9" is not in the registry`},
		{"model data class too low", model("lending", "claude-haiku", "confidential"), false, `model "claude-haiku" is approved for internal data, not confidential`},
		{"team clearance too low", model("wealth", "gpt-4o", "confidential"), false, `team "wealth" is cleared for internal data, not confidential`},
		{"unknown team", model("ghosts", "gpt-4o", "internal"), false, `unknown team "ghosts"`},
		{"unknown data class", model("lending", "claude-sonnet", "top-secret"), false, `unknown data class "top-secret"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := eng.Decide(ctx, tc.in)
			if d.Allow != tc.allow {
				t.Fatalf("allow = %v, reasons %v", d.Allow, d.Reasons)
			}
			if tc.reason != "" && !contains(d.Reasons, tc.reason) {
				t.Fatalf("reasons %v missing %q", d.Reasons, tc.reason)
			}
		})
	}
}

func TestToolAndAgentDecisions(t *testing.T) {
	eng, _ := engine(t, "")
	ctx := context.Background()
	tool := func(team, server, name string) Input {
		return Input{Subject: Subject{Team: team}, Action: ActionTool, Resource: Resource{Name: server, Tool: name}, DataClass: "internal"}
	}
	if d := eng.Decide(ctx, tool("lending", "jira-mcp", "get_issue")); !d.Allow {
		t.Fatalf("lending/jira get_issue: %v", d.Reasons)
	}
	if d := eng.Decide(ctx, tool("lending", "jira-mcp", "update_loan")); d.Allow || !contains(d.Reasons, `tool "jira-mcp" does not expose "update_loan"`) {
		t.Fatalf("outside allow list: %+v", d)
	}
	if d := eng.Decide(ctx, tool("wealth", "jira-mcp", "get_issue")); d.Allow {
		t.Fatal("wealth is not entitled to jira")
	}
	if d := eng.Decide(ctx, tool("lending", "core-banking-mcp", "")); d.Allow || !contains(d.Reasons, `tool "core-banking-mcp" is requested, not approved`) {
		t.Fatalf("unapproved tool: %+v", d)
	}
	agent := func(team string) Input {
		return Input{Subject: Subject{Team: team}, Action: ActionAgent, Resource: Resource{Name: "underwriting-agent"}, DataClass: "internal"}
	}
	if d := eng.Decide(ctx, agent("lending")); !d.Allow {
		t.Fatalf("agent: %v", d.Reasons)
	}
	if d := eng.Decide(ctx, agent("wealth")); d.Allow {
		t.Fatal("agent of another team")
	}
}

func TestLiveRegistryStatusOverridesCDL(t *testing.T) {
	eng, e := engine(t, "")
	status := func(kind, name string) string {
		if kind == "model" && name == "claude-sonnet" {
			return "retired"
		}
		if kind == "model" && name == "llama-70b" {
			return "approved"
		}
		return "approved"
	}
	if err := eng.Load(e, status); err != nil {
		t.Fatal(err)
	}
	d := eng.Decide(context.Background(), model("lending", "claude-sonnet", "internal"))
	if d.Allow || !contains(d.Reasons, `model "claude-sonnet" is retired, not approved`) {
		t.Fatalf("retired: %+v", d)
	}
}

func TestCustomPolicyDir(t *testing.T) {
	dir := t.TempDir()
	custom := `package chautari.custom

import rego.v1

deny contains "high-risk models need a named app" if {
	input.action == "model.invoke"
	data.estate.models[input.resource.name].risk_tier == "medium"
	input.subject.app == "anonymous"
}
`
	os.WriteFile(filepath.Join(dir, "bank.rego"), []byte(custom), 0o644)
	os.WriteFile(filepath.Join(dir, "bank_test.rego"), []byte("this is ignored"), 0o644)
	eng, _ := engine(t, dir)
	in := model("lending", "claude-sonnet", "internal")
	in.Subject.App = "anonymous"
	if d := eng.Decide(context.Background(), in); d.Allow || d.Reasons[0] != "high-risk models need a named app" {
		t.Fatalf("custom deny: %+v", d)
	}
	in.Subject.App = "loan-assistant"
	if d := eng.Decide(context.Background(), in); !d.Allow {
		t.Fatalf("custom allow: %+v", d)
	}
	os.WriteFile(filepath.Join(dir, "broken.rego"), []byte("package x\nthis is not rego"), 0o644)
	if _, err := New(dir); err == nil {
		t.Fatal("broken custom policy must fail to load")
	}
}

// TestRegoUnitTests runs the *_test.rego files with OPA's own test runner.
func TestRegoUnitTests(t *testing.T) {
	ctx := context.Background()
	results, err := tester.Run(ctx, "rego")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 6 {
		t.Fatalf("expected the rego tests to run, got %d results", len(results))
	}
	for _, r := range results {
		if !r.Pass() {
			t.Errorf("%s.%s failed: %v %v", r.Package, r.Name, r.Fail, r.Error)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if strings.Contains(x, want) {
			return true
		}
	}
	return false
}
