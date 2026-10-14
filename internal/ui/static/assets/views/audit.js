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

// Audit log: the hash-chained record, newest first.

import { get, cached, AuthError } from "../api.js";
import { h, replace, int, time, shortHash, pageHead, section, empty, decisionPill, field, select, chainSeal, busy, icons, errorToast, grow } from "../dom.js";

const KINDS = ["request", "tool", "agent", "decision", "approval", "key", "config"];
const DECISIONS = ["allow", "deny", "limit", "block", "redact", "flag", "error", "n/a", "requested", "reviewed", "approved", "rejected", "retired"];
const PAGE = 100;

function detailRow(r, cols) {
  return h("tr.detail", h("td", { colspan: cols },
    h("div.detail-grid",
      h("div",
        h("p.label", "Details"),
        h("pre", JSON.stringify(r.details || {}, null, 2)),
        r.reasons && r.reasons.length > 1 ? [h("p.label", "All reasons"), h("ul.reasons", r.reasons.map((x) => h("li", x)))] : null),
      h("dl.hashes",
        h("dt", "Recorded"), h("dd", new Date(r.ts).toISOString()),
        h("dt", "Previous hash"), h("dd", r.prev_hash),
        h("dt", "Hash"), h("dd", r.hash),
        h("dt", "Actor"), h("dd", r.actor || "—")))));
}

export default async function audit(page, ctx) {
  const q = ctx.query;
  const params = new URLSearchParams({ limit: String(PAGE) });
  for (const k of ["kind", "decision", "subject", "before"]) if (q.get(k)) params.set(k, q.get(k));
  const [records, est] = await Promise.all([get(`/api/audit?${params}`), cached("/api/estate", 60000)]);

  page.append(pageHead({
    eyebrow: "Audit log",
    title: "The record",
    lede: "Append-only and hash-chained: each record's hash covers the one before it, so an edit, a deletion or a reordering anywhere breaks every hash after it. Prompts appear only as SHA-256 digests.",
  }));

  // Chain verification and exports.
  const sealBox = h("div", { "aria-live": "polite" });
  const verify = h("button.button", { type: "button" }, "Verify chain");
  verify.addEventListener("click", () => busy(verify, async () => {
    try {
      replace(sealBox, chainSeal(await get("/api/audit/verify")));
    } catch (ex) {
      if (ex instanceof AuthError) throw ex;
      errorToast(ex);
    }
  }));
  page.append(section("Integrity", { id: "integrity" },
    h("div.integrity",
      h("div.buttons", verify,
        h("a.button.quiet", { href: "/api/audit/export?format=jsonl", download: "" }, "Export JSONL"),
        h("a.button.quiet", { href: "/api/audit/export?format=csv", download: "" }, "Export CSV")),
      sealBox),
    h("p.hint", "Exports are the whole contiguous chain, so they verify anywhere, offline: ", h("code", "chautari audit verify file.jsonl"))));

  // Filters.
  const kind = select([["", "Any kind"], ...KINDS.map((k) => [k, k])], q.get("kind") || "");
  const decision = select([["", "Any decision"], ...DECISIONS.map((d) => [d, d])], q.get("decision") || "");
  const subjects = [];
  for (const t of est.estate.teams) {
    subjects.push(t.name);
    for (const a of est.estate.apps.filter((x) => x.team === t.name)) subjects.push(`${t.name}/${a.name}`);
  }
  const subject = h("input", { type: "search", list: "audit-subjects", value: q.get("subject") || "", placeholder: "team or team/app", autocomplete: "off" });
  const apply = h("button.button", { type: "submit" }, "Filter");
  const reset = h("a.button.quiet", { href: "#/audit" }, "Clear");
  const form = h("form.filters", { role: "search" },
    (field("Kind", kind)),
    (field("Decision", decision)),
    grow(field("Subject", subject)),
    h("datalist", { id: "audit-subjects" }, subjects.map((s) => h("option", { value: s }))),
    h("div.buttons", apply, reset));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const nq = new URLSearchParams();
    if (kind.value) nq.set("kind", kind.value);
    if (decision.value) nq.set("decision", decision.value);
    if (subject.value.trim()) nq.set("subject", subject.value.trim());
    ctx.setQuery(nq);
    ctx.refresh();
  });
  for (const el of [kind, decision]) el.addEventListener("change", () => form.requestSubmit());

  const cols = 8;
  let body;
  if (!records.length) {
    body = empty(q.toString() ? "No records match. Try loosening the filters." : "The log is empty.");
  } else {
    const tbody = h("tbody");
    for (const r of records) {
      const btn = h("button.expander", { type: "button", "aria-expanded": "false", "aria-label": `Show details for record ${r.seq}` }, icons.chevron());
      const row = h("tr",
        h("td.nowrap", btn, h("span.seq", String(r.seq))),
        h("td.nowrap", time(r.ts, "short")),
        h("td", r.kind),
        h("td.actor", h("span", { class: (r.actor || "").startsWith("cdl:") || (r.actor || "").startsWith("key_") ? "mono" : null, title: r.actor }, r.actor || "—")),
        h("td.nowrap", r.subject || h("span.muted", "—")),
        h("td", h("span.nowrap", r.action), h("span.sub.nowrap", r.resource)),
        h("td", decisionPill(r.decision)),
        h("td.wrap", r.reasons && r.reasons.length ? [r.reasons[0], r.reasons.length > 1 ? h("span.muted", ` +${r.reasons.length - 1}`) : null] : h("span.muted", "—")));
      let detail = null;
      btn.addEventListener("click", () => {
        const open = btn.getAttribute("aria-expanded") === "true";
        btn.setAttribute("aria-expanded", String(!open));
        if (open) {
          detail.remove();
        } else {
          detail = detailRow(r, cols);
          row.after(detail);
        }
      });
      tbody.appendChild(row);
    }
    body = h("div.table-wrap", h("table.table.audit",
      h("thead", h("tr", ["Seq", "Time", "Kind", "Actor", "Subject", "Action · resource", "Decision", "Reasons"].map((x) => h("th", { scope: "col" }, x)))),
      tbody));
  }

  const pager = h("nav.pager", { "aria-label": "Pages" });
  const first = records[0];
  const last = records[records.length - 1];
  const older = new URLSearchParams(q);
  if (last) older.set("before", String(last.seq));
  const newest = new URLSearchParams(q);
  newest.delete("before");
  pager.append(
    h("span", records.length ? `Records ${int(last.seq)}–${int(first.seq)}` : ""),
    h("span.buttons",
      q.get("before") ? h("a.button.small", { href: `#/audit${newest.toString() ? "?" + newest : ""}` }, "Newest") : null,
      records.length === PAGE ? h("a.button.small", { href: `#/audit?${older}` }, "Older →") : null));

  page.append(section("Records", { id: "records", aside: q.get("before") ? `before seq ${q.get("before")}` : "newest first" }, form, body, pager));
}
