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

// Overview: the estate at a glance.

import { get, cached } from "../api.js";
import { h, int, usd, compact, time, shortHash, pageHead, section, chainSeal, empty, statusPill } from "../dom.js";
import { stackedColumns, lastDays, seriesFromRows } from "../chart.js";
import { budgetList, blockFeed, teamOrder } from "./shared.js";

function figure(label, value, note, cls) {
  return h("div", { class: ["figure", cls] },
    h("p.figure-label", label),
    h("p.figure-value", value),
    note && h("p.figure-note", note));
}

export default async function overview(page) {
  const [ov, est] = await Promise.all([get("/api/overview"), cached("/api/estate", 60000)]);
  const e = ov.estate;
  const r = ov.recent;
  const denied = r.by_decision.deny || 0;
  const blocked = r.by_decision.block || 0;
  const limited = r.by_decision.limit || 0;
  const redacted = r.by_decision.redact || 0;

  page.append(pageHead({
    eyebrow: `Overview · ${e.environment || "estate"}`,
    title: e.org || e.name,
    lede: `Estate ${e.name}, carried by ${e.dataplane} and governed from ${e.cdl_file}. ${e.teams} teams, ${e.apps} apps and ${e.policies} guardrail policies.`,
    meta: h("div.meta-line",
      h("span", h("b", "CDL "), e.cdl_file, " @ ", h("span.mono", { title: e.cdl_sha256 }, shortHash(e.cdl_sha256, 12))),
      h("span", h("b", "Data plane "), e.dataplane),
      h("span", h("b", "Version "), h("span.mono", e.version || "dev")),
      h("span", h("b", "Up since "), time(e.started_at))),
  }));

  const pending = ov.pending.length;
  page.append(h("div.figures",
    figure("Requests · 24h", int(r.requests), redacted ? `${int(redacted)} with redactions` : "through the checkpoint"),
    figure("Refused · 24h", int(denied + blocked + limited), `${int(denied)} by policy · ${int(blocked)} by guardrails · ${int(limited)} by budgets`, denied + blocked + limited ? "alert" : null),
    figure("Spend · 24h", usd(r.spend_usd), "metered at model prices"),
    figure("Tokens · 24h", compact(r.tokens), "prompt and completion"),
    figure("Active keys", int(ov.keys.active), ov.keys.revoked ? `${int(ov.keys.revoked)} revoked` : "none revoked"),
    figure("Pending approvals", h("a", { href: "#/approvals" }, int(pending)), pending ? "awaiting review" : "nothing waiting", pending ? "attn" : null),
  ));

  const teams = ov.budgets.filter((b) => b.scope === "team");
  const apps = ov.budgets.filter((b) => b.scope === "app");

  const counts = ov.registry || {};
  const left = h("div",
    section("Budgets", { id: "budgets", aside: h("a", { href: "#/spend" }, "Spend detail") },
      budgetList(teams)),
    section("Apps", { id: "app-budgets" }, budgetList(apps)));

  const right = h("div",
    section("Audit chain", { id: "chain", aside: h("a", { href: "#/audit" }, "Audit log") },
      chainSeal(ov.chain),
      h("p.hint", "Every request, decision, approval and key event is hash-chained. Exports verify offline.")),
    section("Waiting on a person", { id: "pending", aside: h("a", { href: "#/approvals" }, "Approvals") },
      pending
        ? h("ul.pending-list", ov.pending.map((p) => h("li",
          h("span", h("span.kind", p.kind), h("span.name", p.name)),
          h("span", statusPill(p.status)))))
        : empty("Nothing is waiting for review.")),
    section("Registry", { id: "registry" },
      h("div.counts", ["model", "tool", "agent"].map((k) => {
        const c = counts[k] || {};
        const parts = ["approved", "requested", "reviewed", "rejected", "retired"].filter((s) => c[s]).map((s) => h("span.count-line", `${c[s]} ${s}`));
        return h("div", h("b", k + "s"), parts.length ? parts : "none");
      }))));

  page.append(h("div.columns", left, right));

  const days = lastDays(14);
  const series = seriesFromRows(ov.daily_spend, teamOrder(est.estate), (x) => x.team, (x) => x.day);
  page.append(section("Daily spend by team", { id: "daily", aside: "last 14 days, UTC" },
    series.length
      ? stackedColumns({ days, series, title: "Daily spend by team over the last 14 days" })
      : empty("No spend recorded in the last fourteen days.")));

  page.append(section("Recent blocks", { id: "blocks", aside: h("a", { href: "#/guardrails" }, "All blocks") },
    blockFeed(r.blocks, "No blocks in the last day. The trail is quiet.")));
}
