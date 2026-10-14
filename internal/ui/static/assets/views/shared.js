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

// shared.js: pieces more than one page draws.

import { h, usd, pct, time, decisionPill, empty } from "../dom.js";

const PERIOD = { day: "day", week: "week", month: "month" };

export function budgetList(statuses) {
  if (!statuses || statuses.length === 0) return empty("No teams or apps declared.");
  return h("ul.budgets", statuses.map(budgetRow));
}

export function budgetRow(b) {
  const has = b.limit_usd > 0;
  const f = has ? b.used_usd / b.limit_usd : 0;
  const level = !has ? "none" : f >= 1 ? "over" : f >= 0.75 ? "warn" : "ok";
  const fill = h("span");
  if (has) fill.style.width = `${Math.min(100, Math.max(0, f * 100)).toFixed(2)}%`;
  const bar = h("div", {
    class: ["bar", level],
    role: has ? "meter" : null,
    "aria-valuemin": has ? 0 : null,
    "aria-valuemax": has ? b.limit_usd : null,
    "aria-valuenow": has ? b.used_usd.toFixed(2) : null,
    "aria-label": has ? `${b.name}: ${usd(b.used_usd)} of ${usd(b.limit_usd)} per ${b.period}` : `${b.name}: no budget`,
    title: has ? `${pct(f)} of the ${b.period}ly budget` : "No budget set; spend shown for the current month",
  }, fill);
  const figs = has
    ? h("div.budget-figs",
      h("span", { class: ["pct", level === "warn" && "warn", level === "over" && "over"] }, pct(f)), " ",
      usd(b.used_usd), h("span.of", ` of ${usd(b.limit_usd, { whole: b.limit_usd >= 100 })} / ${PERIOD[b.period] || b.period}`))
    : h("div.budget-figs", h("span.of", "no budget · "), usd(b.used_usd), h("span.of", " this month"));
  return h("li.budget",
    h("div.budget-name", h("span.scope", b.scope), b.name),
    bar, figs);
}

// blockFeed lists denials and guardrail blocks from audit records.
export function blockFeed(records, emptyText) {
  if (!records || records.length === 0) return empty(emptyText);
  return h("ul.feed", records.map((r) => {
    const reason = (r.reasons && r.reasons[0]) || "";
    return h("li",
      time(r.ts, "clock"),
      h("div.what",
        h("span.who", r.subject || r.actor), h("span.res", " → ", (r.resource || "").replace(/^model\//, "")),
      ),
      decisionPill(r.decision),
      reason && h("div.why", reason));
  }));
}

export function teamOrder(estate) {
  return (estate.teams || []).map((t) => t.name);
}
export function appOrder(estate) {
  return (estate.apps || []).map((a) => a.name);
}
