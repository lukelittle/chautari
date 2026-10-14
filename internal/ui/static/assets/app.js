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

// app.js: shell, hash router and sign-in.

import { AuthError, getActor, signIn, signOut, get, cached, invalidate, whoAmI } from "./api.js";
import { h, replace, field, loading, errorToast } from "./dom.js";

const routes = {
  overview: { title: "Overview", load: () => import("./views/overview.js") },
  estate: { title: "Estate", load: () => import("./views/estate.js") },
  approvals: { title: "Approvals", load: () => import("./views/approvals.js") },
  keys: { title: "Keys", load: () => import("./views/keys.js") },
  guardrails: { title: "Blocks & guardrails", load: () => import("./views/guardrails.js") },
  spend: { title: "Spend", load: () => import("./views/spend.js") },
  audit: { title: "Audit log", load: () => import("./views/audit.js") },
  controls: { title: "Controls", load: () => import("./views/controls.js") },
};

const main = () => document.getElementById("main");
let generation = 0;
let firstRender = true;

export function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, qs = ""] = raw.split("?");
  const [name, ...rest] = path.split("/");
  return { name: routes[name] ? name : "overview", rest, query: new URLSearchParams(qs) };
}

// navigate updates the hash; replace=true does not add a history entry.
export function navigate(name, query, replaceEntry = false) {
  const qs = query && [...query].length ? "?" + query.toString() : "";
  const url = `#/${name}${qs}`;
  if (replaceEntry) {
    history.replaceState(null, "", url);
  } else {
    location.hash = url;
  }
}

async function render() {
  const gen = ++generation;
  const { name, rest, query } = parseHash();
  const route = routes[name];
  document.title = `${route.title} · chautari`;
  for (const a of document.querySelectorAll(".nav a")) {
    if (a.dataset.route === name) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  const root = main();
  const page = h("div.page");
  replace(root, page, loading(`Loading ${route.title}`));
  root.classList.remove("fade");
  if (!firstRender) {
    window.scrollTo(0, 0);
    root.focus({ preventScroll: true });
  }
  firstRender = false;
  try {
    const mod = await route.load();
    if (gen !== generation) return;
    await mod.default(page, {
      rest,
      query,
      alive: () => gen === generation,
      setQuery: (q) => navigate(name, q, true),
      refresh: () => render(),
    });
    if (gen !== generation) return;
    if (page.parentNode === root) {
      for (const n of [...root.childNodes]) if (n !== page) n.remove();
    } else {
      replace(root, page);
    }
    void root.offsetWidth;
    root.classList.add("fade");
    document.body.classList.remove("signed-out", "booting");
    refreshRail();
  } catch (err) {
    if (gen !== generation) return;
    if (err instanceof AuthError) {
      showSignIn();
      return;
    }
    document.body.classList.remove("booting");
    replace(root, h("div.page",
      h("header.page-head", h("p.eyebrow", route.title), h("h1", "This page could not be drawn.")),
      h("div.callout.error", { role: "alert" }, h("strong", "Error: "), err.message || String(err)),
      h("p.hint", "Check that the control plane is running, then reload.")));
  }
}

async function refreshRail() {
  try {
    await whoAmI();
  } catch {
    /* render() reports authentication problems */
  }
  const actor = getActor();
  const actorEl = document.getElementById("rail-actor");
  actorEl.textContent = actor || "unknown";
  actorEl.title = actor;
  try {
    const [est, reg] = await Promise.all([cached("/api/estate", 60000), get("/api/registry")]);
    const s = est.summary;
    replace(document.getElementById("rail-estate"), s.org || s.name, h("br"), h("span.mono", s.environment || ""));
    const pending = reg.filter((e) => e.status === "requested" || e.status === "reviewed").length;
    const badge = document.getElementById("pending-count");
    badge.textContent = String(pending);
    badge.hidden = pending === 0;
    badge.setAttribute("aria-label", `${pending} pending`);
  } catch {
    /* the rail is decoration; the page reports real errors */
  }
}

function showSignIn(message) {
  document.body.classList.add("signed-out");
  document.body.classList.remove("booting");
  const token = h("input", { type: "password", name: "token", autocomplete: "current-password", required: true, spellcheck: "false" });
  const actor = h("input", { type: "text", name: "actor", autocomplete: "email", value: getActor(), placeholder: "you@example.org" });
  const err = h("div.inline-error", { role: "alert", hidden: !message }, message || "");
  const submit = h("button.button.primary", { type: "submit" }, "Sign in");
  const form = h("form", { novalidate: true },
    field("Admin token", token, "Your personal token from CHAUTARI_ADMIN_TOKENS, or the shared CHAUTARI_ADMIN_TOKEN. The token itself never leaves this form; the session lasts twelve hours."),
    field("Your name or email", actor, "Needed only with the shared token: approvals are attributed to you by name. A personal token already says who you are."),
    err, submit);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!token.value) {
      err.hidden = false;
      err.textContent = "Enter the admin token.";
      token.focus();
      return;
    }
    submit.disabled = true;
    submit.textContent = "Signing in…";
    try {
      await signIn(token.value, actor.value.trim());
      invalidate();
      document.body.classList.remove("signed-out");
      render();
    } catch (ex) {
      err.hidden = false;
      err.textContent = ex.status === 401 ? "That admin token was not accepted."
        : ex.status === 400 ? "This is the shared token: tell us who you are, so approvals can be attributed to a person."
        : ex.status === 429 ? "Too many failed attempts. Wait a few minutes, then try again." : ex.message;
      if (ex.status === 400) actor.focus();
      submit.disabled = false;
      submit.textContent = "Sign in";
      token.select();
    }
  });
  const leaf = document.querySelector(".brand .leaf").cloneNode(true);
  replace(main(), h("div.signin",
    h("div.signin-card",
      leaf,
      h("p.eyebrow", "chautari · admin"),
      h("h1", "Sit a while, then sign in."),
      h("p.lede", "A chautari is the stone platform built beneath a pipal tree on Nepal's trails, where anyone may set down a load. This one keeps watch over your AI estate."),
      form,
      h("p.colophon", "Open source, owned by no one. Every action you take here is written to a hash-chained audit log."))));
  (actor.value ? token : actor).focus();
}

document.getElementById("sign-out").addEventListener("click", async () => {
  await signOut();
  invalidate();
  showSignIn();
});

window.addEventListener("hashchange", render);
window.addEventListener("unhandledrejection", (e) => {
  if (e.reason instanceof AuthError) {
    e.preventDefault();
    showSignIn("Your session has ended. Sign in again.");
  } else if (e.reason && e.reason.name === "ApiError") {
    e.preventDefault();
    errorToast(e.reason);
  }
});
if (!location.hash) history.replaceState(null, "", "#/overview");
render();
