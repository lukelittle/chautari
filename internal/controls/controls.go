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

// Package controls maps Chautari's features to AI governance and model risk
// frameworks and produces an evidence-backed report.
//
// The mapping is a starting point for a control owner, not an attestation.
// Each control says what Chautari does, which framework outcomes it supports,
// where the configuration lives, and, when the report is produced by a running
// instance, the live evidence from the registry and the audit log.
package controls

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"time"

	"github.com/lukelittle/chautari/internal/estate"
)

// Ref is a citation of a framework outcome or section.
type Ref struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Text      string `json:"text"`
}

// Frameworks cited by the catalogue.
const (
	NIST  = "NIST AI RMF 1.0"
	SR117 = "SR 11-7"
)

// Control is one Chautari capability and its mappings.
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Mechanism   string   `json:"mechanism"` // where it is implemented / configured
	Refs        []Ref    `json:"refs"`
	Config      []string `json:"config"`   // estate facts that configure it
	Evidence    []string `json:"evidence"` // live facts, when available
	Status      string   `json:"status"`   // "in place", "not configured", or "partial: …" / "attention: …" from live evidence
}

// Evidence is live state from a running control plane. All fields optional.
type Evidence struct {
	GeneratedAt     time.Time
	RegistryCounts  map[string]map[string]int // kind -> status -> count
	AuditByKind     map[string]int
	AuditByDecision map[string]int
	AuditRecords    int64
	ChainOK         bool
	ChainHead       string
	ChainChecked    int64
	ActiveKeys      int
	RevokedKeys     int
	Approvals       []string // recent approval lines, newest first
	SpendByTeam     map[string]float64
	// ActorsVerified is true when admin actions are attributed to
	// per-person admin tokens rather than self-declared names.
	ActorsVerified bool
}

// Report is the full controls report.
type Report struct {
	Estate      string    `json:"estate"`
	Org         string    `json:"org"`
	CDLSHA256   string    `json:"cdl_sha256"`
	Live        bool      `json:"live"`
	GeneratedAt time.Time `json:"generated_at,omitempty"`
	Controls    []Control `json:"controls"`
}

var (
	govern16   = Ref{NIST, "GOVERN 1.6", "Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities."}
	govern14   = Ref{NIST, "GOVERN 1.4", "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities."}
	govern21   = Ref{NIST, "GOVERN 2.1", "Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the organization."}
	govern61   = Ref{NIST, "GOVERN 6.1", "Policies and procedures are in place that address AI risks associated with third-party entities."}
	measure24  = Ref{NIST, "MEASURE 2.4", "The functionality and behavior of the AI system and its components are monitored when in production."}
	measure27  = Ref{NIST, "MEASURE 2.7", "AI system security and resilience are evaluated and documented."}
	measure210 = Ref{NIST, "MEASURE 2.10", "Privacy risk of the AI system is examined and documented."}
	manage24   = Ref{NIST, "MANAGE 2.4", "Mechanisms are in place and applied, and responsibilities are assigned and understood, to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use."}
	manage31   = Ref{NIST, "MANAGE 3.1", "AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented."}
	manage41   = Ref{NIST, "MANAGE 4.1", "Post-deployment AI system monitoring plans are implemented."}

	srInventory    = Ref{SR117, "Governance, Policies, and Controls: model inventory", "Banks should maintain a comprehensive set of information for models implemented for use, under development for implementation, or recently retired."}
	srChallenge    = Ref{SR117, "Overview of Model Risk Management: effective challenge", "Effective challenge depends on a combination of incentives, competence, and influence."}
	srIndependence = Ref{SR117, "Model Validation: independence", "Validation involves a degree of independence from model development and use."}
	srMonitoring   = Ref{SR117, "Model Validation: ongoing monitoring", "Ongoing monitoring confirms the model is appropriately implemented and is being used and performing as intended."}
	srPolicies     = Ref{SR117, "Governance, Policies, and Controls: policies and procedures", "Policies should define relevant risk management activities and the processes for model development, implementation, use, and validation."}
	srRoles        = Ref{SR117, "Governance, Policies, and Controls: roles and responsibilities", "Model risk governance should assign clear roles and responsibilities, including for model owners, users, and control staff."}
	srVendor       = Ref{SR117, "Model Validation: vendor and other third-party products", "Vendor products should be incorporated into a bank's broader model risk management framework following the same principles as applied to in-house models."}
	srDocs         = Ref{SR117, "Governance, Policies, and Controls: documentation", "Documentation of model development and validation should be sufficiently detailed so that parties unfamiliar with a model can understand how it operates."}
	srAudit        = Ref{SR117, "Governance, Policies, and Controls: internal audit", "Internal audit should assess the overall effectiveness of the model risk management framework and verify that records of model use and validation are kept."}
)

// Build assembles the report. ev may be nil for a static (CDL-only) report.
func Build(e *estate.Estate, ev *Evidence) Report {
	r := Report{Estate: e.Name, Org: e.Org, CDLSHA256: e.Source.SHA256, Live: ev != nil}
	if ev != nil {
		r.GeneratedAt = ev.GeneratedAt
	}
	count := func(kind string, approved bool) int {
		n := 0
		switch kind {
		case "model":
			for _, m := range e.Models {
				if m.Approved == approved {
					n++
				}
			}
		case "tool":
			for _, t := range e.Tools {
				if t.Approved == approved {
					n++
				}
			}
		}
		return n
	}
	var budgets, rates, guarded []string
	for _, t := range e.Teams {
		if t.Budget != nil {
			budgets = append(budgets, fmt.Sprintf("team %s: %s USD/%s", t.Name, usd(t.Budget.USD), t.Budget.Period))
		}
		for _, rt := range t.Rates {
			rates = append(rates, fmt.Sprintf("team %s: %s", t.Name, rt))
		}
	}
	for _, a := range e.Apps {
		if a.Budget != nil {
			budgets = append(budgets, fmt.Sprintf("app %s: %s USD/%s", a.Name, usd(a.Budget.USD), a.Budget.Period))
		}
		if a.KeyBudget != nil {
			budgets = append(budgets, fmt.Sprintf("each %s key: %s USD/%s", a.Name, usd(a.KeyBudget.USD), a.KeyBudget.Period))
		}
		for _, rt := range a.Rates {
			rates = append(rates, fmt.Sprintf("app %s: %s", a.Name, rt))
		}
	}
	detectors := map[string]bool{}
	for _, p := range e.Policies {
		var parts []string
		for _, rule := range p.Rules {
			parts = append(parts, fmt.Sprintf("%s %s %s", rule.Action, rule.Direction, strings.Join(rule.Detectors, ",")))
			for _, d := range rule.Detectors {
				detectors[d] = true
			}
		}
		scope := "all teams"
		if len(p.AppliesTo) > 0 {
			scope = strings.Join(p.AppliesTo, ", ")
		}
		guarded = append(guarded, fmt.Sprintf("policy %s (%s): %s", p.Name, scope, strings.Join(parts, "; ")))
	}
	var providers []string
	for _, p := range e.Providers {
		providers = append(providers, fmt.Sprintf("%s (%s)", p.Name, p.Type))
	}
	var entitlements []string
	for _, t := range e.Teams {
		entitlements = append(entitlements, fmt.Sprintf("team %s, cleared for %s: models [%s], tools [%s]",
			t.Name, t.Clearance, strings.Join(t.Models, ", "), strings.Join(t.Tools, ", ")))
	}
	var owners []string
	for _, t := range e.Teams {
		if t.Owner != "" {
			owners = append(owners, fmt.Sprintf("team %s owned by %s", t.Name, t.Owner))
		}
	}
	for _, t := range e.Tools {
		if len(t.Owners) > 0 {
			owners = append(owners, fmt.Sprintf("tool %s owned by %s", t.Name, strings.Join(t.Owners, ", ")))
		}
	}

	ctl := []Control{
		{
			ID: "CH-01", Title: "AI estate inventory",
			Description: "Every model, MCP tool and agent is declared in a version-controlled CDL file and held in a registry with its owner, data classification, risk tier and lifecycle status, including retired entries.",
			Mechanism:   "estate.cdl, internal/registry, /api/registry",
			Refs:        []Ref{govern16, srInventory, srDocs},
			Config: []string{
				fmt.Sprintf("%d models (%d approved in CDL), %d MCP tools, %d agents", len(e.Models), count("model", true), len(e.Tools), len(e.Agents)),
				fmt.Sprintf("estate source: %s, sha256 %s", e.Source.File, short(e.Source.SHA256)),
			},
		},
		{
			ID: "CH-02", Title: "Independent approval workflow",
			Description: "Entries move requested → reviewed → approved → retired. The API refuses a review or approval by the requester, and an approval by the reviewer. Approver identities come from per-person admin tokens (CHAUTARI_ADMIN_TOKENS); with a single shared token they are self-declared. CDL-declared approvals are attributed to the CDL file's hash, so the merged change request is the approval record.",
			Mechanism:   "internal/registry (separation of duties enforced in code)",
			Refs:        []Ref{srChallenge, srIndependence, govern14, govern21},
			Config:      []string{fmt.Sprintf("%d models awaiting approval in CDL", count("model", false))},
		},
		{
			ID: "CH-03", Title: "Policy-as-code access control",
			Description: "Every model invocation, tool call and agent call is decided by OPA against the estate: the resource must be approved, the team entitled, and both the resource and the team cleared for the request's data class. Decisions fail closed.",
			Mechanism:   "internal/policy/rego/authz.rego (exported to policy/ by the generator)",
			Refs:        []Ref{govern14, srPolicies, measure27},
			Config:      entitlements,
		},
		{
			ID: "CH-04", Title: "Guardrails on prompts and completions",
			Description: "Configurable filters detect PII (SSN, payment cards with Luhn validation, email, phone, IBAN, AWS keys), prompt-injection patterns and blocked topics, with redact, block or flag actions, and can delegate to Amazon Bedrock Guardrails. A filter error blocks the request.",
			Mechanism:   "internal/guardrails, policy blocks in estate.cdl",
			Refs:        []Ref{measure210, measure27, srPolicies},
			Config:      guarded,
		},
		{
			ID: "CH-05", Title: "Spend budgets and rate limits",
			Description: "Spend is metered per request from token usage and model price, and enforced per team, app and key over calendar windows. Token and request rate limits cap bursts.",
			Mechanism:   "internal/budget, budget/rate in estate.cdl",
			Refs:        []Ref{manage41, govern14},
			Config:      append(budgets, rates...),
		},
		{
			ID: "CH-06", Title: "Tamper-evident audit log",
			Description: "Every request, policy decision, guardrail action, approval and key event is appended to a SHA-256 hash chain. The database rejects UPDATE, DELETE and TRUNCATE on the log. Exports verify offline with `chautari audit verify`. Prompts and completions are stored only as digests.",
			Mechanism:   "internal/audit, audit_log table triggers, /api/audit/export",
			Refs:        []Ref{srAudit, measure24, srDocs},
		},
		{
			ID: "CH-07", Title: "Kill switch",
			Description: "Retiring a model, tool or agent removes it from policy decisions and the data plane's routing configuration without a deployment: immediately on the replica that handles the request, and on other replicas within one resync interval (15 s by default).",
			Mechanism:   "registry retire action → policy reload + gateway config re-render",
			Refs:        []Ref{manage24},
		},
		{
			ID: "CH-08", Title: "Production monitoring",
			Description: "The control plane and agentgateway emit OpenTelemetry traces; the admin UI shows spend against budget, policy blocks and guardrail hits per team.",
			Mechanism:   "otel/collector.yaml, admin UI",
			Refs:        []Ref{measure24, manage41, srMonitoring},
		},
		{
			ID: "CH-09", Title: "Third-party model and tool governance",
			Description: "External providers and MCP servers are reachable only through the data plane, which holds their credentials and exposes only approved models and tools. Applications never hold provider keys.",
			Mechanism:   "dataplane adapter (agentgateway), provider blocks in estate.cdl",
			Refs:        []Ref{govern61, manage31, srVendor},
			Config:      []string{"providers: " + strings.Join(providers, ", ")},
		},
		{
			ID: "CH-10", Title: "Accountability",
			Description: "Teams, tools and models carry named owners; every audit record names its actor (a person, an API key id, or a CDL file hash).",
			Mechanism:   "owner fields in estate.cdl, audit actor",
			Refs:        []Ref{govern21, srRoles},
			Config:      owners,
		},
	}

	for i := range ctl {
		c := &ctl[i]
		c.Status = "in place"
		if len(c.Config) == 0 && (c.ID == "CH-04" || c.ID == "CH-05") {
			c.Status = "not configured"
		}
		if ev != nil {
			c.Evidence = evidence(c.ID, ev, detectors)
			switch {
			case c.ID == "CH-06" && !ev.ChainOK:
				c.Status = "attention: chain broken"
			case c.ID == "CH-02" && !ev.ActorsVerified:
				c.Status = "partial: approvers self-declared"
			}
		}
		sort.SliceStable(c.Refs, func(a, b int) bool { return c.Refs[a].Framework < c.Refs[b].Framework })
	}
	r.Controls = ctl
	return r
}

func evidence(id string, ev *Evidence, detectors map[string]bool) []string {
	var out []string
	switch id {
	case "CH-01", "CH-02":
		kinds := make([]string, 0, len(ev.RegistryCounts))
		for k := range ev.RegistryCounts {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			var parts []string
			for _, s := range []string{"requested", "reviewed", "approved", "rejected", "retired"} {
				if n := ev.RegistryCounts[k][s]; n > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", n, s))
				}
			}
			out = append(out, fmt.Sprintf("%ss: %s", k, strings.Join(parts, ", ")))
		}
		if id == "CH-02" {
			if ev.ActorsVerified {
				out = append(out, "Approver identities are bound to per-person admin tokens.")
			} else {
				out = append(out, "Admin access uses a shared token; approver names are self-declared, so separation of duties is advisory. Configure per-person admin tokens (CHAUTARI_ADMIN_TOKENS) to enforce it.")
			}
			out = append(out, fmt.Sprintf("%d approval events in the audit log", ev.AuditByKind["approval"]))
			for i, a := range ev.Approvals {
				if i == 5 {
					break
				}
				out = append(out, a)
			}
		}
	case "CH-03":
		out = append(out, fmt.Sprintf("%d requests allowed, %d denied by policy", ev.AuditByDecision["allow"], ev.AuditByDecision["deny"]))
	case "CH-04":
		out = append(out, fmt.Sprintf("%d blocked, %d redacted, %d flagged by guardrails", ev.AuditByDecision["block"], ev.AuditByDecision["redact"], ev.AuditByDecision["flag"]))
	case "CH-05":
		teams := make([]string, 0, len(ev.SpendByTeam))
		for t := range ev.SpendByTeam {
			teams = append(teams, t)
		}
		sort.Strings(teams)
		for _, t := range teams {
			out = append(out, fmt.Sprintf("team %s: %s USD this month", t, usd(ev.SpendByTeam[t])))
		}
		out = append(out, fmt.Sprintf("%d active keys, %d revoked", ev.ActiveKeys, ev.RevokedKeys))
	case "CH-06":
		state := "VERIFIED"
		if !ev.ChainOK {
			state = "BROKEN"
		}
		out = append(out, fmt.Sprintf("%d records; chain %s over %d records; head %s", ev.AuditRecords, state, ev.ChainChecked, short(ev.ChainHead)))
	case "CH-07":
		out = append(out, fmt.Sprintf("%d entries currently retired", ev.RegistryCounts["model"]["retired"]+ev.RegistryCounts["tool"]["retired"]+ev.RegistryCounts["agent"]["retired"]))
	case "CH-08":
		out = append(out, fmt.Sprintf("%d model requests recorded", ev.AuditByKind["request"]))
	}
	return out
}

func usd(f float64) string { return fmt.Sprintf("%.2f", f) }

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

// Markdown renders the report for a repository or an auditor's inbox.
func Markdown(r Report) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# AI Controls Report: %s\n\n", r.Org)
	if r.Live {
		fmt.Fprintf(&b, "Generated by Chautari from a running control plane at %s.\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "Generated by Chautari from the estate definition. Run `chautari report controls --server …`\nagainst a running control plane to attach live evidence from the registry and audit log.\n")
	}
	fmt.Fprintf(&b, "\nEstate `%s`, CDL sha256 `%s`.\n\n", r.Estate, r.CDLSHA256)
	b.WriteString("> This report maps Chautari's technical controls to NIST AI RMF 1.0 outcomes and to the\n")
	b.WriteString("> supervisory guidance on model risk management (SR 11-7). It supports, and does not replace,\n")
	b.WriteString("> your control owners' assessment.\n\n")

	b.WriteString("## Summary\n\n| Control | Status | NIST AI RMF | SR 11-7 |\n|---|---|---|---|\n")
	for _, c := range r.Controls {
		var nist, sr []string
		for _, ref := range c.Refs {
			if ref.Framework == NIST {
				nist = append(nist, ref.ID)
			} else {
				sr = append(sr, strings.SplitN(ref.ID, ": ", 2)[len(strings.SplitN(ref.ID, ": ", 2))-1])
			}
		}
		fmt.Fprintf(&b, "| %s %s | %s | %s | %s |\n", c.ID, c.Title, c.Status, strings.Join(nist, ", "), strings.Join(sr, "; "))
	}
	for _, c := range r.Controls {
		fmt.Fprintf(&b, "\n## %s %s\n\n%s\n\n**Implemented by:** %s\n\n", c.ID, c.Title, c.Description, c.Mechanism)
		b.WriteString("**Maps to:**\n\n")
		for _, ref := range c.Refs {
			fmt.Fprintf(&b, "- %s, %s: %s\n", ref.Framework, ref.ID, ref.Text)
		}
		if len(c.Config) > 0 {
			b.WriteString("\n**Configured in this estate:**\n\n")
			for _, s := range c.Config {
				fmt.Fprintf(&b, "- %s\n", s)
			}
		}
		if len(c.Evidence) > 0 {
			b.WriteString("\n**Live evidence:**\n\n")
			for _, s := range c.Evidence {
				fmt.Fprintf(&b, "- %s\n", s)
			}
		}
	}
	return b.Bytes()
}

// HTML renders the report as a standalone printable page.
func HTML(r Report) ([]byte, error) {
	var b bytes.Buffer
	err := htmlTmpl.Execute(&b, r)
	return b.Bytes(), err
}

var htmlTmpl = template.Must(template.New("controls").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Controls Report: {{.Org}}</title>
<style>
body{font:15px/1.55 "Iowan Old Style","Palatino Linotype",Georgia,serif;color:#2b2a26;background:#f4f0e8;margin:0}
main{max-width:860px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:30px;margin:0 0 6px;font-weight:600}h2{font-size:19px;margin:36px 0 8px;border-top:1px solid #d9d1c2;padding-top:20px}
.flags{height:6px;background:linear-gradient(90deg,#2b5fa8 0 20%,#f4f0e8 20% 40%,#b5412f 40% 60%,#3d7a4f 60% 80%,#d9a53a 80%)}
.meta{color:#6b665c;font-size:13px;font-family:ui-monospace,Menlo,monospace}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:16px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #e2dacb;vertical-align:top}
.ok{color:#2f5d3a;font-weight:600}.no{color:#b5412f;font-weight:600}
ul{padding-left:20px}li{margin:3px 0}.k{font-family:ui-monospace,Menlo,monospace;font-size:12.5px}
blockquote{margin:16px 0;padding:10px 16px;background:#ebe4d6;border-left:3px solid #2f5d3a;font-size:13.5px}
@media print{body{background:#fff}.flags{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
</style></head><body><div class="flags"></div><main>
<h1>AI Controls Report</h1>
<div class="meta">{{.Org}} · estate {{.Estate}} · cdl sha256 {{.CDLSHA256}}{{if .Live}} · live evidence {{.GeneratedAt.UTC.Format "2006-01-02 15:04 MST"}}{{end}}</div>
<blockquote>Maps Chautari's technical controls to NIST AI RMF 1.0 outcomes and the supervisory guidance on model risk management (SR 11-7). It supports, and does not replace, your control owners' assessment.</blockquote>
<table><tr><th>Control</th><th>Status</th><th>References</th></tr>
{{range .Controls}}<tr><td>{{.ID}} {{.Title}}</td><td class="{{if eq .Status "in place"}}ok{{else}}no{{end}}">{{.Status}}</td><td class="k">{{range $i, $r := .Refs}}{{if $i}}, {{end}}{{$r.ID}}{{end}}</td></tr>
{{end}}</table>
{{range .Controls}}<h2>{{.ID}} {{.Title}}</h2><p>{{.Description}}</p><p><b>Implemented by:</b> <span class="k">{{.Mechanism}}</span></p>
<ul>{{range .Refs}}<li><b>{{.Framework}} {{.ID}}</b>: {{.Text}}</li>{{end}}</ul>
{{if .Config}}<p><b>Configured in this estate</b></p><ul>{{range .Config}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Evidence}}<p><b>Live evidence</b></p><ul>{{range .Evidence}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{end}}</main></body></html>`))
