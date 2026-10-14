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

// Estate: the inventory, as declared in CDL and amended through approvals.

import { get, post, cached } from "../api.js";
import { h, replace, usd, compact, shortHash, pageHead, empty, dcPill, statusPill, tags, loading } from "../dom.js";

const DETECTORS = {
  ssn: "SSNs", card: "payment cards", email: "email addresses", phone: "phone numbers", iban: "IBANs",
  aws_key: "AWS keys", "aws-key": "AWS keys", injection: "prompt injection", topic: "blocked topics", bedrock: "Bedrock guardrail",
};

export function describeRules(rules) {
  // CDL "both" compiles to one rule per direction; fold them back together.
  const groups = new Map();
  for (const r of rules || []) {
    const k = r.action + "|" + (r.detectors || []).join(",");
    if (!groups.has(k)) groups.set(k, { action: r.action, detectors: r.detectors || [], dirs: [] });
    groups.get(k).dirs.push(r.direction);
  }
  return [...groups.values()].map((g) => {
    const dir = g.dirs.length > 1 ? "both ways" : g.dirs[0];
    return `${g.action} ${dir}: ${g.detectors.map((d) => DETECTORS[d] || d).join(", ")}`;
  });
}

const rate = (r) => `${compact(r.limit)} ${r.unit}/${r.period}`;
const budget = (b) => (b ? `${usd(b.usd, { whole: b.usd >= 100 })} / ${b.period}` : null);
const muted = (t = "—") => h("span.muted", t);

function nameCell(name, sub) {
  return h("td", h("span.name", name), sub && h("span.sub", sub));
}

function table(headers, rows) {
  return h("div.table-wrap", h("table.table",
    h("thead", h("tr", headers.map((x) => {
      const [label, cls] = Array.isArray(x) ? x : [x];
      return h("th", { scope: "col", class: cls }, label);
    }))),
    h("tbody", rows)));
}

function status(st, kind, name) {
  return statusPill(st[`${kind}/${name}`] || "unknown");
}

const TABS = [
  ["models", "Models"], ["tools", "Tools"], ["agents", "Agents"], ["teams", "Teams"],
  ["apps", "Apps"], ["policies", "Policies"], ["providers", "Providers"], ["access", "Access"],
];

function panels(est, st) {
  const e = est;
  return {
    models: () => (e.models.length ? table(["Model", "Provider", "Upstream id", "Data class", "Risk", ["In / Mtok", "num"], ["Out / Mtok", "num"], "Status"],
      e.models.map((m) => h("tr",
        nameCell(m.name, m.description),
        h("td", m.provider),
        h("td", h("code", m.upstream_id || "—")),
        h("td", dcPill(m.data_class)),
        h("td", h("span", { class: ["risk", `risk-${m.risk_tier}`] }, m.risk_tier || "—")),
        h("td.num", usd(m.cost_in_usd_per_mtok)),
        h("td.num", usd(m.cost_out_usd_per_mtok)),
        h("td", status(st, "model", m.name)))))
      : empty("No models declared.")),
    tools: () => (e.tools.length ? table(["Tool", "Scope", "Owners", "Allowed calls", "Data class", "Status"],
      e.tools.map((t) => h("tr",
        nameCell(t.name, t.description || t.endpoint),
        h("td", t.scope === "write" ? h("strong", "write") : t.scope),
        h("td", tags(t.owners)),
        h("td.wrap", t.allow && t.allow.length ? tags(t.allow, true) : muted("every tool on the server")),
        h("td", dcPill(t.data_class)),
        h("td", status(st, "tool", t.name)))))
      : empty("No MCP tools declared.")),
    agents: () => (e.agents.length ? table(["Agent", "Team", "Model", "Tools", "Endpoint", "Status"],
      e.agents.map((a) => h("tr",
        nameCell(a.name, a.description),
        h("td", a.team),
        h("td", a.model || muted()),
        h("td", tags(a.tools)),
        h("td", a.endpoint ? h("code", a.endpoint) : muted()),
        h("td", status(st, "agent", a.name)))))
      : empty("No A2A agents declared.")),
    teams: () => table(["Team", "Models", "Tools", "Clearance", "Budget", "Rates"],
      e.teams.map((t) => h("tr",
        nameCell(t.name, t.owner),
        h("td.wrap", tags(t.models)),
        h("td", tags(t.tools)),
        h("td", dcPill(t.clearance)),
        h("td.nowrap", budget(t.budget) || muted("no budget")),
        h("td.nowrap", t.rates && t.rates.length ? t.rates.map(rate).join(", ") : muted())))),
    apps: () => table(["App", "Team", "Default data class", "Budget", "Per-key budget", "Rates"],
      e.apps.map((a) => h("tr",
        nameCell(a.name, a.description),
        h("td", a.team),
        h("td", a.data_class ? dcPill(a.data_class) : h("span", dcPill(e.default_data_class), h("span.muted", " (estate)"))),
        h("td.nowrap", budget(a.budget) || muted("no budget")),
        h("td.nowrap", budget(a.key_budget) || muted()),
        h("td.nowrap", a.rates && a.rates.length ? a.rates.map(rate).join(", ") : muted())))),
    policies: () => (e.policies.length ? table(["Policy", "Rules", "Topics", "Applies to"],
      e.policies.map((p) => h("tr",
        nameCell(p.name, p.description || (p.bedrock_guardrail ? `Bedrock guardrail ${p.bedrock_guardrail}` : null)),
        h("td.wrap", h("ul.reasons", describeRules(p.rules).map((x) => h("li", x)))),
        h("td", p.topics && p.topics.length ? tags(p.topics) : muted()),
        h("td", p.applies_to && p.applies_to.length ? tags(p.applies_to) : muted("every team")))))
      : empty("No guardrail policies. Every prompt passes through untouched.")),
    providers: () => table(["Provider", "Type", "Region", "Endpoint", "Credential"],
      e.providers.map((p) => h("tr",
        nameCell(p.name),
        h("td", p.type),
        h("td", p.region || muted()),
        h("td", p.endpoint ? h("code", p.endpoint) : muted()),
        h("td", p.api_key_env ? h("code", "$" + p.api_key_env) : muted("held by the data plane"))))),
    access: () => accessMatrix(e),
  };
}

function accessMatrix(e) {
  const box = h("div", loading("Asking the policy engine"));
  const dc = "internal";
  (async () => {
    const teams = e.teams.map((t) => t.name);
    const models = e.models.map((m) => m.name);
    const matrix = await get(`/api/policy/matrix?data_class=${encodeURIComponent(dc)}`);
    const cells = teams.flatMap((t) => models.map((m) => ({ t, m, d: (matrix.teams[t] || {})[m] || { allow: false, reasons: ["no decision"] } })));
    const at = (t, m) => cells.find((c) => c.t === t && c.m === m).d;
    const denials = cells.filter((c) => !c.d.allow);
    replace(box,
      h("p.section-note", `Each cell is a live dry-run decision from the policy engine for a request at `, dcPill(dc), ` data class. Nothing is audited.`),
      h("div.table-wrap", h("table.table.matrix",
        h("caption.visually-hidden", "Which teams may invoke which models"),
        h("thead", h("tr", h("th", { scope: "col" }, "Team ↓ · model →"), models.map((m) => h("th", { scope: "col" }, m)))),
        h("tbody", teams.map((t) => h("tr", h("th", { scope: "row" }, t), models.map((m) => {
          const d = at(t, m);
          const why = d.allow ? "allowed" : (d.reasons || []).join("; ") || "denied";
          return h("td", h("span", { class: ["cell", d.allow ? "yes" : "no"], tabindex: 0, title: why, role: "img", "aria-label": `${t} → ${m}: ${why}` }, d.allow ? "✓" : "✕"));
        })))))),
      denials.length
        ? h("ul.denials", denials.map((c) => h("li", h("b", `${c.t} × ${c.m}`), " — ", (c.d.reasons || []).join("; "))))
        : null);
  })().catch((err) => replace(box, h("div.callout.error", { role: "alert" }, h("strong", "Could not draw the matrix: "), err.message)));
  return box;
}

export default async function estate(page, ctx) {
  const data = await cached("/api/estate", 5000);
  await get("/api/registry"); // freshness check; also surfaces auth errors early
  const e = data.estate;
  const st = data.status || {};
  const p = panels(e, st);

  page.append(pageHead({
    eyebrow: `Estate · ${data.summary.name}`,
    title: "The inventory",
    lede: "Everything this control plane governs: declared in CDL, reviewed in a pull request, and amended only through recorded approvals.",
    meta: h("div.meta-line",
      h("span", h("b", "Source "), data.summary.cdl_file, " @ ", h("span.mono", { title: data.summary.cdl_sha256 }, shortHash(data.summary.cdl_sha256))),
      h("span", h("b", "Region "), e.region || "—"),
      h("span", h("b", "Default data class "), e.default_data_class)),
  }));

  const counts = {
    models: e.models.length, tools: e.tools.length, agents: e.agents.length, teams: e.teams.length,
    apps: e.apps.length, policies: e.policies.length, providers: e.providers.length,
  };
  let current = TABS.some(([k]) => k === ctx.query.get("tab")) ? ctx.query.get("tab") : "models";
  const panel = h("div", { role: "tabpanel", id: "estate-panel", tabindex: 0 });
  const buttons = TABS.map(([key, label]) => h("button.tab", {
    type: "button", role: "tab", id: `tab-${key}`, "aria-controls": "estate-panel", dataset: { key },
  }, label, counts[key] !== undefined && h("span.n", String(counts[key]))));
  const list = h("div.tabs", { role: "tablist", "aria-label": "Estate sections" }, buttons);

  const show = (key, focus) => {
    current = key;
    for (const b of buttons) {
      const on = b.dataset.key === key;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    }
    panel.setAttribute("aria-labelledby", `tab-${key}`);
    replace(panel, p[key]());
  };
  list.addEventListener("click", (ev) => {
    const b = ev.target.closest("button.tab");
    if (!b) return;
    show(b.dataset.key);
    const q = new URLSearchParams(ctx.query);
    q.set("tab", b.dataset.key);
    ctx.setQuery(q);
  });
  list.addEventListener("keydown", (ev) => {
    const i = TABS.findIndex(([k]) => k === current);
    let j = null;
    if (ev.key === "ArrowRight") j = (i + 1) % TABS.length;
    if (ev.key === "ArrowLeft") j = (i - 1 + TABS.length) % TABS.length;
    if (ev.key === "Home") j = 0;
    if (ev.key === "End") j = TABS.length - 1;
    if (j === null) return;
    ev.preventDefault();
    show(TABS[j][0], true);
  });
  page.append(list, panel);
  show(current);
}
