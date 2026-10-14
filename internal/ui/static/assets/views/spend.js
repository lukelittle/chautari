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

// Spend: metered cost against budgets, by team or by app.

import { get, cached } from "../api.js";
import { h, usd, int, compact, pct, pageHead, section, empty } from "../dom.js";
import { stackedColumns, lastDays, seriesFromRows } from "../chart.js";
import { budgetList, teamOrder, appOrder } from "./shared.js";

export default async function spend(page, ctx) {
  const scope = ctx.query.get("scope") === "app" ? "app" : "team";
  const [budgets, rows, est] = await Promise.all([
    get("/api/budgets"),
    get(`/api/spend?scope=${scope}&period=day`),
    cached("/api/estate", 30000),
  ]);
  const mine = budgets.filter((b) => b.scope === scope);
  const order = scope === "team" ? teamOrder(est.estate) : appOrder(est.estate);
  const day = (r) => r.window_start.slice(0, 10);
  const days = lastDays(30);
  const series = seriesFromRows(rows, order, (r) => r.subject, day);
  const total30 = rows.reduce((a, r) => a + r.usd, 0);

  const seg = h("div.seg", { role: "group", "aria-label": "Group spend by" }, ["team", "app"].map((sc) => {
    const b = h("button", { type: "button", "aria-pressed": String(sc === scope) }, sc === "team" ? "By team" : "By app");
    b.addEventListener("click", () => {
      if (sc === scope) return;
      const q = new URLSearchParams(ctx.query);
      q.set("scope", sc);
      ctx.setQuery(q);
      ctx.refresh();
    });
    return b;
  }));

  page.append(pageHead({
    eyebrow: "Spend",
    title: "What the estate has cost",
    lede: "Usage tokens times model price, metered on every request, including the ones whose answers a guardrail withheld. Budgets are enforced per team, app and key over calendar windows.",
    meta: h("div.meta-line", h("span", h("b", usd(total30)), " in the last 30 days"), h("span", h("b", int(rows.reduce((a, r) => a + r.requests, 0))), " metered requests")),
  }));

  page.append(h("div.toolbar", seg));

  page.append(section(`Daily spend by ${scope}`, { id: "chart", aside: "last 30 days, UTC" },
    series.length ? stackedColumns({ days, series, title: `Daily spend by ${scope} over the last 30 days` }) : empty("No spend recorded in the last thirty days.")));

  page.append(section("Against budget", { id: "budgets", aside: "current window" }, budgetList(mine)));

  const by = new Map();
  for (const r of rows) by.set(r.subject, (by.get(r.subject) || 0) + r.usd);
  page.append(section("Ledger", { id: "ledger" },
    mine.length ? h("div.table-wrap", h("table.table",
      h("thead", h("tr", [scope === "team" ? "Team" : "App", "Budget", "Used this window", "Share", "Tokens", "Requests", "30 days"].map((x, i) => h("th", { scope: "col", class: i > 0 ? "num" : null }, x)))),
      h("tbody", mine.map((b) => h("tr",
        h("td", h("span.name", b.name)),
        h("td.num", b.limit_usd > 0 ? `${usd(b.limit_usd, { whole: b.limit_usd >= 100 })} / ${b.period}` : h("span.muted", "none")),
        h("td.num", usd(b.used_usd, { precise: true })),
        h("td.num", b.limit_usd > 0 ? pct(b.used_usd / b.limit_usd) : h("span.muted", "—")),
        h("td.num", compact(b.tokens)),
        h("td.num", int(b.requests)),
        h("td.num", usd(by.get(b.name) || 0, { precise: true }))))),
      h("tfoot", h("tr", h("td", "Total"), h("td"), h("td.num", usd(mine.reduce((a, b) => a + b.used_usd, 0))), h("td"),
        h("td.num", compact(mine.reduce((a, b) => a + b.tokens, 0))), h("td.num", int(mine.reduce((a, b) => a + b.requests, 0))), h("td.num", usd(total30))))))
      : empty("Nothing to show.")));
}
