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

// Approvals: the registry lifecycle, with separation of duties.

import { get, post, cached, invalidate, AuthError, getActor } from "../api.js";
import { h, replace, usd, time, pageHead, section, empty, dcPill, statusPill, field, select, toast, confirmDialog, busy, icons, dataClasses } from "../dom.js";

const NEXT = {
  requested: ["review", "reject"],
  reviewed: ["approve", "reject"],
  approved: ["retire"],
  rejected: ["request"],
  retired: ["request"],
};
const LABEL = { review: "Mark reviewed", approve: "Approve", reject: "Reject", retire: "Retire", request: "Request again" };
const ORDER = { requested: 0, reviewed: 1, approved: 2, rejected: 3, retired: 4 };

function parseSpec(e) {
  if (!e.spec) return {};
  if (typeof e.spec === "object") return e.spec;
  try {
    return JSON.parse(e.spec);
  } catch {
    return {};
  }
}

// who renders an actor; CDL actors ("cdl:file@sha") read as the file.
function who(actor) {
  const m = /^cdl:(.+)@([0-9a-f]+)$/.exec(actor || "");
  if (!m) return h("span.who", actor);
  return h("span.who", { title: actor }, m[1], " ", h("span.mono", "@" + m[2].slice(0, 8)));
}

function trail(e) {
  const step = (label, actor, done) => h("li", { class: done ? "done" : null },
    h("span.dot", { "aria-hidden": "true" }),
    h("span", h("span.step", label), actor ? h("span", " by ", who(actor)) : null));
  const asCode = e.requested_by && e.requested_by.startsWith("cdl:") && e.approved_by === e.requested_by;
  if (asCode) {
    return h("ol.trail", { "aria-label": "Lifecycle" },
      step("approved as code", e.approved_by, true),
      e.status === "retired" ? step("retired", null, true) : null);
  }
  return h("ol.trail", { "aria-label": "Lifecycle" },
    step("requested", e.requested_by, true),
    step("reviewed", e.reviewed_by, Boolean(e.reviewed_by)),
    e.status === "rejected"
      ? step("rejected", null, true)
      : e.status === "retired"
        ? [step("approved", e.approved_by, true), step("retired", null, true)]
        : step("approved", e.approved_by, e.status === "approved"));
}

function specLine(kind, sp) {
  if (kind === "model") {
    return h("div.entry-spec",
      sp.provider && h("span", h("b", "provider "), sp.provider),
      sp.upstream_id && h("span", h("b", "id "), h("code", sp.upstream_id)),
      sp.data_class && h("span", dcPill(sp.data_class)),
      sp.risk_tier && h("span", h("b", "risk "), sp.risk_tier),
      (sp.cost_in_usd_per_mtok || sp.cost_out_usd_per_mtok) ? h("span", h("b", "cost "), `${usd(sp.cost_in_usd_per_mtok)} in · ${usd(sp.cost_out_usd_per_mtok)} out per Mtok`) : null);
  }
  if (kind === "tool") {
    return h("div.entry-spec",
      sp.scope && h("span", h("b", "scope "), sp.scope),
      sp.owners && sp.owners.length ? h("span", h("b", "owners "), sp.owners.join(", ")) : null,
      sp.data_class && h("span", dcPill(sp.data_class)));
  }
  return h("div.entry-spec",
    sp.team && h("span", h("b", "team "), sp.team),
    sp.model && h("span", h("b", "model "), sp.model));
}

function entryCard(e, reload) {
  const sp = parseSpec(e);
  const actions = NEXT[e.status] || [];
  const note = h("input", { type: "text", id: `note-${e.kind}-${e.name}`, placeholder: "Why? (recorded in the audit log)", maxlength: 500 });
  const err = h("div.inline-error", { role: "alert", hidden: true });

  const run = async (action, btn) => {
    err.hidden = true;
    if (action === "retire") {
      const ok = await confirmDialog({
        title: `Retire ${e.name}?`,
        body: "This removes the model from every policy decision and the gateway immediately.",
        ok: "Retire now",
      });
      if (!ok) return;
    }
    if (action === "reject") {
      const ok = await confirmDialog({ title: `Reject ${e.name}?`, body: "It can be requested again later; the rejection is recorded with your name.", ok: "Reject" });
      if (!ok) return;
    }
    await busy(btn, async () => {
      try {
        await post(`/api/registry/${encodeURIComponent(e.kind)}/${encodeURIComponent(e.name)}/${action}`, { note: note.value.trim() });
        invalidate("/api/estate");
        toast(`${e.kind} ${e.name}: ${action === "request" ? "requested again" : action + (action.endsWith("e") ? "d" : "ed")}.`);
        reload();
      } catch (ex) {
        if (ex instanceof AuthError) throw ex;
        replace(err, ex.status === 403
          ? h("div.sod", icons.stop(), h("div", h("strong", "Separation of duties."), " ", ex.message.replace(/^separation of duties:\s*/i, "")))
          : h("span", h("strong", ex.status === 409 ? "Not now." : "Failed."), " ", ex.message));
        err.hidden = false;
      }
    });
  };

  const buttons = actions.map((a) => {
    const b = h("button", { type: "button", class: ["button", "small", a === "approve" && "primary", (a === "retire" || a === "reject") && "danger"] }, LABEL[a]);
    b.addEventListener("click", () => run(a, b));
    return b;
  });

  return h("li.entry",
    h("div",
      h("div.entry-head", h("span.entry-kind", e.kind), statusPill(e.status), e.source === "api" ? h("span.tag", "via API") : h("span.tag", "declared in CDL")),
      h("h3.entry-name", e.name),
      sp.description && h("p.entry-desc", sp.description),
      specLine(e.kind, sp),
      trail(e),
      e.note && !(e.source === "cdl" && e.note.startsWith("declared in")) && h("p.entry-note", e.note),
      h("p.hint", "Updated ", time(e.updated_at))),
    h("div.entry-act",
      actions.length ? [h("label", { for: `note-${e.kind}-${e.name}` }, "Note"), note, h("div.buttons", buttons), err] : null));
}

function requestForm(est, reload) {
  const providers = est.providers.map((p) => p.name);
  const name = h("input", { type: "text", required: true, placeholder: "e.g. mistral-large", pattern: "[a-z0-9][a-z0-9-]*", autocomplete: "off" });
  const provider = select(providers, providers[0]);
  const upstream = h("input", { type: "text", placeholder: "provider's model id", autocomplete: "off" });
  const dc = select(dataClasses(), "internal");
  const risk = select(["low", "medium", "high"], "medium");
  const cin = h("input", { type: "number", min: 0, step: "0.01", value: "0", inputmode: "decimal" });
  const cout = h("input", { type: "number", min: 0, step: "0.01", value: "0", inputmode: "decimal" });
  const desc = h("input", { type: "text", placeholder: "What it is for" });
  const note = h("input", { type: "text", placeholder: "Business case, ticket link" });
  const err = h("div.inline-error", { role: "alert", hidden: true });
  const submit = h("button.button.primary", { type: "submit" }, "Submit request");
  const form = h("form.panel", { novalidate: true },
    h("div.form-grid",
      field("Name", name, "Lowercase, as callers will use it."),
      field("Provider", provider),
      field("Upstream id", upstream),
      field("Data class", dc, "The most sensitive data it may see."),
      field("Risk tier", risk),
      field("Cost in, USD / Mtok", cin),
      field("Cost out, USD / Mtok", cout),
      h("div.wide", field("Description", desc)),
      h("div.wide", field("Note", note))),
    err,
    h("div.buttons.form-actions", submit, h("span.hint", `Requested by ${getActor() || "you"}. Someone else must review it, and a third person approve it.`)));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    if (!name.value.trim()) {
      err.textContent = "Give the model a name.";
      err.hidden = false;
      name.focus();
      return;
    }
    await busy(submit, async () => {
      try {
        await post("/api/registry", {
          kind: "model", name: name.value.trim(), note: note.value.trim(),
          spec: {
            provider: provider.value, upstream_id: upstream.value.trim(), data_class: dc.value, risk_tier: risk.value,
            cost_in_usd_per_mtok: Number(cin.value) || 0, cost_out_usd_per_mtok: Number(cout.value) || 0, description: desc.value.trim(),
          },
        });
        invalidate("/api/estate");
        toast(`Model ${name.value.trim()} requested. It needs an independent review.`);
        form.reset();
        reload();
      } catch (ex) {
        if (ex instanceof AuthError) throw ex;
        err.textContent = ex.message;
        err.hidden = false;
      }
    });
  });
  return form;
}

export default async function approvals(page, ctx) {
  const [entries, est] = await Promise.all([get("/api/registry"), cached("/api/estate", 30000)]);
  const sorted = entries.slice().sort((a, b) => (ORDER[a.status] - ORDER[b.status]) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
  const pending = sorted.filter((e) => e.status === "requested" || e.status === "reviewed");
  const approved = sorted.filter((e) => e.status === "approved");
  const closed = sorted.filter((e) => e.status === "rejected" || e.status === "retired");
  const reload = () => ctx.refresh();

  page.append(pageHead({
    eyebrow: "Approvals",
    title: "Who said yes, and who checked",
    lede: "Models, tools and agents move from requested to reviewed to approved. The person who asks cannot review; the reviewer cannot approve. Retiring something takes effect at once.",
    meta: h("div.meta-line", h("span", h("b", `${pending.length} `), "waiting"), h("span", h("b", `${approved.length} `), "approved"), h("span", h("b", `${closed.length} `), "rejected or retired")),
  }));

  page.append(section("Waiting on a decision", { id: "pending" },
    pending.length ? h("ul.entries", pending.map((e) => entryCard(e, reload))) : empty("Nothing is waiting. Every request has had its say.")));
  page.append(section("Request a model", { id: "request", note: "Requests land in the registry as requested. Nothing routes to the model until it is approved." },
    requestForm(est.estate, reload)));
  page.append(section("In service", { id: "approved" },
    approved.length ? h("ul.entries", approved.map((e) => entryCard(e, reload))) : empty("Nothing is approved yet.")));
  if (closed.length) {
    page.append(section("Rejected and retired", { id: "closed" }, h("ul.entries", closed.map((e) => entryCard(e, reload)))));
  }
}
