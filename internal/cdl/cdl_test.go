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
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lukelittle/chautari/internal/estate"
)

// The exact example from the project brief must compile.
const briefExample = `
provider bedrock { type bedrock }
model claude-sonnet { provider bedrock, approved true, data-class internal }
tool jira-mcp { endpoint "http://jira:8080/mcp", scope read, owners [platform-team] }
policy pii { redact inbound, block outbound ssn, card }
team lending { models [claude-sonnet], budget 2000 usd/month, tools [jira-mcp] }
team platform-team { models [claude-sonnet] }
`

func TestBriefExample(t *testing.T) {
	e, err := Compile("brief.cdl", briefExample)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	m, ok := e.Model("claude-sonnet")
	if !ok || !m.Approved || m.DataClass != estate.Internal || m.Provider != "bedrock" {
		t.Fatalf("model = %+v", m)
	}
	team, _ := e.Team("lending")
	if team.Budget == nil || team.Budget.USD != 2000 || team.Budget.Period != estate.Month {
		t.Fatalf("budget = %+v", team.Budget)
	}
	if strings.Join(team.Tools, ",") != "jira-mcp" {
		t.Fatalf("tools = %v", team.Tools)
	}
	tool, _ := e.Tool("jira-mcp")
	if tool.Scope != "read" || strings.Join(tool.Owners, ",") != "platform-team" {
		t.Fatalf("tool = %+v", tool)
	}

	// Bare-list rule: `block outbound ssn, card` keeps card in the block rule.
	pol := e.Policies[0]
	if len(pol.Rules) != 2 {
		t.Fatalf("rules = %+v", pol.Rules)
	}
	var redact, block estate.Rule
	for _, r := range pol.Rules {
		switch r.Action {
		case estate.Redact:
			redact = r
		case estate.Block:
			block = r
		}
	}
	if redact.Direction != estate.Inbound || strings.Join(redact.Detectors, ",") != strings.Join(sorted(PIIDetectors), ",") {
		t.Fatalf("redact = %+v", redact)
	}
	if block.Direction != estate.Outbound || strings.Join(block.Detectors, ",") != "card,ssn" {
		t.Fatalf("block = %+v", block)
	}
}

func sorted(in []string) []string { return dedupe(append([]string(nil), in...)) }

func TestExampleEstateCompiles(t *testing.T) {
	b, err := os.ReadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	e, err := Compile("himalayan-bank.cdl", string(b))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if e.Name != "himalayan-bank" || e.Org != "Himalayan Bank" || e.Dataplane != "agentgateway" {
		t.Fatalf("estate header = %+v", e)
	}
	if len(e.Models) != 4 || len(e.Teams) != 3 || len(e.Apps) != 3 || len(e.Tools) != 2 || len(e.Agents) != 1 {
		t.Fatalf("counts: models=%d teams=%d apps=%d tools=%d agents=%d", len(e.Models), len(e.Teams), len(e.Apps), len(e.Tools), len(e.Agents))
	}
	lending, _ := e.Team("lending")
	if len(lending.Rates) != 1 || lending.Rates[0].Limit != 200_000 || lending.Rates[0].Unit != estate.Tokens {
		t.Fatalf("rates = %+v", lending.Rates)
	}
	app, _ := e.App("loan-assistant")
	if app.KeyBudget == nil || app.KeyBudget.USD != 25 || app.KeyBudget.Period != estate.Day {
		t.Fatalf("key budget = %+v", app.KeyBudget)
	}
	m, _ := e.Model("claude-sonnet")
	if m.CostInUSD != 3 || m.CostOutUSD != 15 || m.UpstreamID != "claude-sonnet-4-5" {
		t.Fatalf("model = %+v", m)
	}
	if got := len(e.PoliciesFor("wealth")); got != 3 {
		t.Fatalf("wealth policies = %d", got)
	}
	if got := len(e.PoliciesFor("lending")); got != 2 {
		t.Fatalf("lending policies = %d", got)
	}
	if e.Source.SHA256 == "" || !strings.HasPrefix(e.Source.Actor(), "cdl:himalayan-bank.cdl@") {
		t.Fatalf("source = %+v", e.Source)
	}
}

func TestCompileIsDeterministic(t *testing.T) {
	a, err := Compile("a.cdl", briefExample)
	if err != nil {
		t.Fatal(err)
	}
	// Reordered declarations, same meaning.
	reordered := `
team platform-team { models [claude-sonnet] }
team lending { tools [jira-mcp], budget 2000 usd/month, models [claude-sonnet] }
policy pii { block outbound card, ssn, redact inbound }
tool jira-mcp { owners [platform-team], scope read, endpoint "http://jira:8080/mcp" }
model claude-sonnet { data-class internal, approved true, provider bedrock }
provider bedrock { type bedrock }
`
	b, err := Compile("a.cdl", reordered)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("digests differ:\n%s\n---\n%s", a.JSON(), b.JSON())
	}
}

func TestQuantitiesAndComments(t *testing.T) {
	src := `
/* block comment */
# hash comment
provider p { type openai }  // trailing
model m { provider p, cost-in 0.25 usd/mtok, cost-out 1.5m usd/mtok }
team t { models [m], rate 20k tokens/min, 100 requests/min, budget 10 usd/day }
app a { team t, rate [5k tokens/hour], key-budget 1 usd/week }
`
	e, err := Compile("q.cdl", src)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := e.Model("m")
	if m.CostInUSD != 0.25 || m.CostOutUSD != 1_500_000 {
		t.Fatalf("prices = %v %v", m.CostInUSD, m.CostOutUSD)
	}
	if got := m.Cost(1_000_000, 0); got != 0.25 {
		t.Fatalf("cost = %v", got)
	}
	team, _ := e.Team("t")
	if len(team.Rates) != 2 || team.Rates[1].Unit != estate.Requests || team.Rates[1].Limit != 100 {
		t.Fatalf("rates = %+v", team.Rates)
	}
	p, _ := e.Provider("p")
	if p.APIKeyEnv != "P_API_KEY" {
		t.Fatalf("api key env = %q", p.APIKeyEnv)
	}
}

func TestErrorsAreHelpful(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"unknown ref with suggestion",
			`provider p { type openai }
model claude-sonnet { provider p }
team lending { models [claude-sonet] }`,
			[]string{`e.cdl:3:24: team "lending" references unknown model "claude-sonet"`, `did you mean "claude-sonnet"?`}},
		{"unknown key",
			`team t { budgte 10 usd/month }`,
			[]string{`unknown property "budgte" for team`, `did you mean "budget"?`}},
		{"bad data class",
			`team t { clearance secret }`,
			[]string{`invalid clearance secret`}},
		{"bad kind",
			`modle m { }
team t { }`,
			[]string{`expected a declaration`, `did you mean "model"?`}},
		{"duplicate",
			`team t { }
team t { }`,
			[]string{`team "t" is declared twice`, `first declared at 1:1`}},
		{"bad budget",
			`team t { budget 10 eur/month }`,
			[]string{`expects a spend quantity`}},
		{"unknown detector",
			`policy p { block inbound ssm }
team t { }`,
			[]string{`unknown detector "ssm"`, `did you mean "ssn"?`}},
		{"topic without topics",
			`policy p { block inbound topic }
team t { }`,
			[]string{`lists no topics`}},
		{"agent entitlement",
			`provider p { type openai }
model m { provider p }
team t { }
agent a { team t, model m }`,
			[]string{`agent "a" uses model "m", which team "t" is not entitled to`}},
		{"unterminated block",
			`team t { models [] `,
			[]string{`team t is never closed`}},
		{"no teams", `provider p { type openai }`, []string{`declares no teams`}},
		{"openai-compatible needs endpoint", `provider p { type openai-compatible }
team t { }`, []string{`needs an endpoint`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile("e.cdl", tc.src)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q\nmissing %q", err.Error(), w)
				}
			}
		})
	}
}

func TestAllErrorsReported(t *testing.T) {
	_, err := Compile("e.cdl", `
team a { models [nope1] }
team b { models [nope2] }
team c { clearance nope3 }`)
	list, ok := err.(ErrorList)
	if !ok || len(list) != 3 {
		t.Fatalf("want 3 errors, got %v", err)
	}
}

func TestBareListThenKnownKey(t *testing.T) {
	e, err := Compile("e.cdl", `
policy p { flag both email, phone, applies-to [t], description "x" }
team t { }`)
	if err != nil {
		t.Fatal(err)
	}
	p := e.Policies[0]
	if len(p.Rules) != 2 || strings.Join(p.Rules[0].Detectors, ",") != "email,phone" || p.AppliesTo[0] != "t" || p.Description != "x" {
		t.Fatalf("policy = %+v", p)
	}
}

// compileErr compiles src and returns the error text, failing if it compiles.
func compileErr(t *testing.T, src string) string {
	t.Helper()
	_, err := Compile("e.cdl", src)
	if err == nil {
		t.Fatalf("expected an error compiling:\n%s", src)
	}
	return err.Error()
}

func wantErr(t *testing.T, src string, want ...string) {
	t.Helper()
	got := compileErr(t, src)
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("error %q\nmissing %q", got, w)
		}
	}
}

func TestEmptyListsAreErrors(t *testing.T) {
	wantErr(t, `tool x { endpoint "http://x/mcp", allow [] }
team t { }`, `tool "x" has an empty allow list`, "omit allow to expose every tool")
	wantErr(t, `policy p { block inbound ssn, applies-to [] }
team t { }`, `empty applies-to list`, "omit applies-to to apply the policy to every team")
	wantErr(t, `policy p { block inbound topic, topics [""] }
team t { }`, `policy "p" has a blank topic`)
	wantErr(t, `policy p { block inbound topic, topics ["  ", "ok"] }
team t { }`, `policy "p" has a blank topic`)
	wantErr(t, `policy p { block inbound topic, topics [] }
team t { }`, `policy "p" has an empty topics list`)
}

func TestAzureNeedsHTTPSEndpoint(t *testing.T) {
	wantErr(t, `provider az { type azure }
team t { }`, `provider "az" of type azure needs an endpoint`)
	wantErr(t, `provider az { type azure, endpoint "http://x.openai.azure.com" }
team t { }`, `needs an https endpoint`)
	if _, err := Compile("e.cdl", `provider az { type azure, endpoint "https://x.openai.azure.com" }
team t { }`); err != nil {
		t.Fatal(err)
	}
}

func TestToolNamesHaveNoUnderscore(t *testing.T) {
	wantErr(t, `tool jira_mcp { endpoint "http://x/mcp" }
team t { }`, `tool name "jira_mcp" contains '_'`, "like jira-mcp")
	// Upstream tool names in allow may use '_'.
	if _, err := Compile("e.cdl", `tool jira-mcp { endpoint "http://x/mcp", allow [search_issues] }
team t { }`); err != nil {
		t.Fatal(err)
	}
}

func TestStringsRejectUnsafeContent(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{`model m { provider p, description "a\nb" }`, `unknown escape \n`},
		{`model m { provider p, description "a\tb" }`, `unknown escape \t`},
		{"model m { provider p, description \"a\tb\" }", `m.description: string "a\tb" contains control character U+0009`},
		{"model m { provider p, description \"a\x01b\" }", `m.description: string "a\x01b" contains control character`},
		{`model m { provider p, description "{{ .Values.x }}" }`, `m.description: string "{{ .Values.x }}" contains "{{"`},
		{`model m { provider p, description "a }} b" }`, `contains "}}"`},
		{`model m { provider p, description "a [[ b" }`, `contains "[["`},
		{`model m { provider p, description "a ]] b" }`, `contains "]]"`},
		{`model m { provider p, id "${HOME}" }`, `m.id: string "${HOME}" contains "${"`},
		{`policy x { block inbound topic, topics ["ok", "{{x}}"] }`, `x.topics: string "{{x}}"`},
	} {
		wantErr(t, "provider p { type openai }\nteam t { }\n"+tc.src, tc.want)
	}
	if _, err := Compile("e.cdl", `provider p { type openai }
model m { provider p, description "Plain \"quoted\" text with $5, {braces} and [brackets]\\" }
team t { }`); err != nil {
		t.Fatal(err)
	}
}

func TestAPIKeyEnvIsAnEnvName(t *testing.T) {
	for _, bad := range []string{`openai_key`, `"1KEY"`, `"A-B"`, `"A B"`, `"${X}"`} {
		wantErr(t, "provider p { type openai, api-key-env "+bad+" }\nteam t { }", "is not a valid environment variable name")
	}
	e, err := Compile("e.cdl", `provider p { type openai, api-key-env OPENAI_API_KEY }
team t { }`)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := e.Provider("p"); p.APIKeyEnv != "OPENAI_API_KEY" {
		t.Fatalf("api-key-env = %q", p.APIKeyEnv)
	}
}

func TestIdentifiersAreASCII(t *testing.T) {
	// "tеam" with a Cyrillic е would otherwise be a second team.
	wantErr(t, `team team { }
team tеam { }`, `identifier "tеam" contains non-ASCII characters`, "identifiers are ASCII; use a string for display names")
	wantErr(t, `team café { }`, `identifier "café"`)
	wantErr(t, `team t { owner bänk }`, `identifier "bänk"`)
	// A trailing '.' or '-' is not part of the identifier.
	wantErr(t, `team t- { }`, `unexpected character '-'`)
}

func TestUppercaseMagnitudeSuffix(t *testing.T) {
	e, err := Compile("e.cdl", `provider p { type openai }
model m { provider p, cost-out 1.5M usd/mtok }
team t { models [m], rate 20K tokens/min }`)
	if err != nil {
		t.Fatal(err)
	}
	team, _ := e.Team("t")
	m, _ := e.Model("m")
	if team.Rates[0].Limit != 20_000 || m.CostOutUSD != 1_500_000 {
		t.Fatalf("rates = %+v, cost-out = %v", team.Rates, m.CostOutUSD)
	}
}

func TestRepeatedDirectivesAreIndependent(t *testing.T) {
	// The second block has no direction; it must not inherit outbound.
	wantErr(t, `policy p { block outbound ssn, block card }
team t { }`, `p.block is missing a direction`)

	e, err := Compile("e.cdl", `policy p { block inbound ssn, card, block outbound email, redact both phone }
team t { }`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range e.Policies[0].Rules {
		got = append(got, fmt.Sprintf("%s %s %s", r.Action, r.Direction, strings.Join(r.Detectors, ",")))
	}
	want := "block inbound card,ssn|redact inbound phone|block outbound email|redact outbound phone"
	if strings.Join(got, "|") != want {
		t.Fatalf("rules = %q, want %q", got, want)
	}
}

func TestRatesAreWholeAndDistinct(t *testing.T) {
	wantErr(t, `team t { rate 1.9 requests/min }`, `t.rate must be a whole number, got 1.9 requests/min`)
	wantErr(t, `team t { rate 20k tokens/min, 10k tokens/min }`, `two tokens/min limits on team t; keep one`)
	wantErr(t, `team t { rate 20k tokens/min, rate [10k tokens/min] }`, `two tokens/min limits on team t; keep one`)
	wantErr(t, `team t { }
app a { team t, rate 5 requests/hour, 6 requests/hour }`, `two requests/hour limits on app a; keep one`)
	e, err := Compile("e.cdl", `team t { rate 1.5k tokens/min, 20k tokens/hour, 10 requests/min, rate 100 requests/hour }`)
	if err != nil {
		t.Fatal(err)
	}
	if team, _ := e.Team("t"); len(team.Rates) != 4 || team.Rates[0].Limit != 1500 {
		t.Fatalf("rates = %+v", team.Rates)
	}
}

func TestAgentEndpoint(t *testing.T) {
	const pre = "team t { }\nagent a { team t, endpoint "
	for _, ok := range []string{"mock-llm:8090", "10.0.0.1:80", "[::1]:9000", "http://agent", "https://agent.example.com/a2a/v1", "http://agent:8080/", "https://[::1]:8443/x"} {
		if _, err := Compile("e.cdl", pre+`"`+ok+`" }`); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"mock-llm", "mock-llm:0", "mock-llm:99999", "host:http", "/path", "ftp://agent", "http://", "http://agent/x?y=1",
		"https://agent/#frag", "http://user:pw@agent", "http://agent:/x", "agent:80/path", "http://bad_host/", "http://agent:+80"} {
		wantErr(t, pre+`"`+bad+`" }`, "must be host:port or an http(s) URL without query or fragment")
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "_", "claude-sonnet", "gpt-4o.mini", "us_east_1", "A9", strings.Repeat("a", 63)} {
		if !ValidName(ok) {
			t.Errorf("ValidName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "9a", "-a", ".a", "a-", "a.", "a b", "a/b", "tеam", "café", "a\n", strings.Repeat("a", 64)} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true", bad)
		}
	}
	// Every valid name lexes back as itself.
	for _, n := range []string{"claude-sonnet", "gpt-4o.mini", "_x"} {
		if e, err := Compile("e.cdl", "team "+n+" { }"); err != nil || e.Teams[0].Name != n {
			t.Errorf("%s: %v", n, err)
		}
	}
	wantErr(t, "team "+strings.Repeat("a", 64)+" { }", "is longer than 63 characters")
}

func FuzzCompile(f *testing.F) {
	f.Add(briefExample)
	f.Add(`team t { rate 1k tokens/min, budget 1 usd/day }`)
	f.Add(`policy p { block inbound "x", [a, b] }`)
	f.Add(`agent a { team t, endpoint "https://h:1/x" } team tеam { rate 1.9 requests/min }`)
	f.Fuzz(func(t *testing.T, src string) {
		_, _ = Compile("fuzz.cdl", src) // must never panic or hang
	})
}
