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

// Keys: API keys for apps. Secrets are shown once and never again.

import { get, post, del, cached, AuthError } from "../api.js";
import { h, replace, time, pageHead, section, empty, field, select, toast, confirmDialog, busy, copy, dcRank, errorToast, grow } from "../dom.js";

function pickModel(est, status, appName) {
  const app = est.apps.find((a) => a.name === appName);
  if (!app) return null;
  const team = est.teams.find((t) => t.name === app.team);
  if (!team) return null;
  const need = dcRank(app.data_class || est.default_data_class);
  const models = team.models.map((n) => est.models.find((m) => m.name === n)).filter(Boolean);
  const live = models.filter((m) => status[`model/${m.name}`] === "approved");
  const cleared = live.find((m) => dcRank(m.data_class) >= need);
  return (cleared || live[0] || models[0] || {}).name || null;
}

function curlExample(secret, model, app) {
  const body = JSON.stringify({ model: model || "MODEL", messages: [{ role: "user", content: `Hello from ${app}` }] });
  return [
    `curl -sS ${window.location.origin}/v1/chat/completions \\`,
    `  -H "Authorization: Bearer ${secret}" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '${body}'`,
  ].join("\n");
}

function secretBox(issued, model) {
  const copyKey = h("button.button.small", { type: "button" }, "Copy key");
  const curl = curlExample(issued.secret, model, issued.app);
  const copyCurl = h("button.button.small", { type: "button" }, "Copy");
  copyKey.addEventListener("click", () => copy(issued.secret, copyKey));
  copyCurl.addEventListener("click", () => copy(curl, copyCurl));
  return h("div.secret", { role: "region", "aria-label": "New API key", tabindex: -1 },
    h("h3", `Key for ${issued.app} issued`),
    h("p", h("strong", "Copy it now. You won't see this again: "), "chautari stores only a SHA-256 hash of the key. If it is lost, revoke it and issue another."),
    h("div.secret-value", h("code", issued.secret), copyKey),
    h("p", "Try it", model ? ` (${model} is the first model ${issued.team} may use at this app's data class):` : ":"),
    h("div.code-wrap", h("pre.codeblock", curl), copyCurl));
}

export default async function keys(page, ctx) {
  const [list, est] = await Promise.all([get("/api/keys"), cached("/api/estate", 30000)]);
  const e = est.estate;
  const active = list.filter((k) => !k.revoked_at);

  page.append(pageHead({
    eyebrow: "Keys",
    title: "Keys to the checkpoint",
    lede: "Each key belongs to one app, and each app to one team. The key carries the team's entitlements, budgets and guardrails with it. Revocation is immediate.",
    meta: h("div.meta-line", h("span", h("b", `${active.length} `), "active"), h("span", h("b", `${list.length - active.length} `), "revoked")),
  }));

  // Issue form.
  const app = select(e.apps.map((a) => [a.name, `${a.name} (${a.team})`]), e.apps[0] && e.apps[0].name);
  const name = h("input", { type: "text", placeholder: "default", maxlength: 64, autocomplete: "off" });
  const submit = h("button.button.primary", { type: "submit" }, "Issue key");
  const result = h("div", { "aria-live": "polite" });
  const form = h("form.panel", { novalidate: true },
    h("div.form-row", field("App", app), grow(field("Key name", name, "Where it will live, e.g. prod, staging, laptop-jane.")), h("div.field.submit-field", submit)),
    result);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    await busy(submit, async () => {
      try {
        const issued = await post("/api/keys", { app: app.value, name: name.value.trim() || "default" });
        const box = secretBox(issued, pickModel(e, est.status || {}, issued.app));
        replace(result, box);
        box.focus();
        name.value = "";
        refreshTable();
      } catch (ex) {
        if (ex instanceof AuthError) throw ex;
        errorToast(ex);
      }
    });
  });
  page.append(section("Issue a key", { id: "issue" }, form));

  const tableBox = h("div");
  const draw = (rows) => {
    const sorted = rows.slice().sort((a, b) => (!!a.revoked_at - !!b.revoked_at) || b.created_at.localeCompare(a.created_at));
    if (sorted.length === 0) return replace(tableBox, empty("No keys yet. Issue one above and the first request can follow."));
    replace(tableBox, h("div.table-wrap", h("table.table",
      h("thead", h("tr", ["Key", "Name", "App", "Team", "Issued by", "Issued", "Status", ""].map((x) => h("th", { scope: "col" }, x)))),
      h("tbody", sorted.map((k) => {
        let action = null;
        if (!k.revoked_at) {
          action = h("button.button.small.danger", { type: "button", "aria-label": `Revoke key ${k.prefix} for ${k.app}` }, "Revoke");
          action.addEventListener("click", async () => {
            const ok = await confirmDialog({ title: `Revoke ${k.prefix}…?`, body: `Requests from ${k.app} using this key will be refused from now on. This cannot be undone.`, ok: "Revoke key" });
            if (!ok) return;
            await busy(action, async () => {
              try {
                await del(`/api/keys/${encodeURIComponent(k.id)}`);
                toast(`Key ${k.prefix}… revoked.`);
                refreshTable();
              } catch (ex) {
                if (ex instanceof AuthError) throw ex;
                errorToast(ex);
              }
            });
          });
        }
        return h("tr",
          h("td", h("code", { title: k.id }, k.prefix + "…")),
          h("td", k.name),
          h("td", k.app),
          h("td", k.team),
          h("td", k.created_by),
          h("td.nowrap", time(k.created_at)),
          h("td.nowrap", k.revoked_at ? h("span", h("span.pill.s-retired", "revoked"), " ", h("span.muted", time(k.revoked_at, "relative"))) : h("span.pill.ok", "active")),
          h("td.num", action));
      })))));
  };
  const refreshTable = async () => {
    try {
      draw(await get("/api/keys"));
    } catch (ex) {
      if (ex instanceof AuthError) throw ex;
      errorToast(ex);
    }
  };
  draw(list);
  page.append(section("All keys", { id: "list" }, tableBox));
  void ctx;
}
