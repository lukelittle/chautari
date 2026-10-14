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

// dom.js: building DOM safely, formatting, and shared page furniture.
// Server data only ever reaches the page as text nodes or attribute values.

const SVG_NS = "http://www.w3.org/2000/svg";

function append(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false || k === true) continue;
    if (Array.isArray(k)) append(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
}

function setAttrs(el, attrs) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.setAttribute("class", Array.isArray(v) ? v.filter(Boolean).join(" ") : v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "style") throw new Error("inline styles are not allowed; use classes or el.style");
    else if (k === "value" && "value" in el) el.value = v;
    else if (k === "checked" || k === "selected" || k === "disabled") el[k] = Boolean(v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}

function isAttrs(x) {
  return x && typeof x === "object" && !(x instanceof Node) && !Array.isArray(x);
}

// h("tag.class", {attrs}, ...children)
export function h(tag, attrs, ...kids) {
  const [name, ...classes] = tag.split(".");
  const el = document.createElement(name || "div");
  if (classes.length) el.className = classes.join(" ");
  if (isAttrs(attrs)) {
    if (attrs.class && classes.length) attrs = { ...attrs, class: [classes.join(" "), attrs.class].flat().filter(Boolean).join(" ") };
    setAttrs(el, attrs);
  } else if (attrs !== undefined) kids.unshift(attrs);
  append(el, kids);
  return el;
}

export function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  if (isAttrs(attrs)) setAttrs(el, attrs);
  else if (attrs !== undefined) kids.unshift(attrs);
  append(el, kids);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function replace(el, ...kids) {
  clear(el);
  append(el, kids);
  return el;
}

// ── formatting ─────────────────────────────────────────────────────────────

const nf = new Intl.NumberFormat(undefined);
export const int = (n) => nf.format(Math.round(Number(n) || 0));

export function usd(n, opts = {}) {
  const v = Number(n) || 0;
  let digits = 2;
  if (opts.precise && v > 0 && v < 1) digits = 4;
  if (opts.whole) digits = 0;
  return "$" + v.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

export function compact(n) {
  const v = Number(n) || 0;
  if (Math.abs(v) < 10000) return int(v);
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(v);
}

export const pct = (f) => `${Math.round((Number(f) || 0) * 100)}%`;

export function shortHash(hash, n = 12) {
  if (!hash) return "";
  return hash.length > n ? hash.slice(0, n) : hash;
}

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const tf = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const sf = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const df = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });

export function utcString(d) {
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

// time renders a <time> with local text and the UTC instant on hover.
export function time(iso, style = "full") {
  if (!iso || iso.startsWith("0001-")) return h("span.muted", "—");
  const d = new Date(iso);
  let text;
  if (style === "relative") text = relative(d);
  else if (style === "short") text = sf.format(d);
  else if (style === "clock") text = sameDay(d, new Date()) ? tf.format(d) : df.format(d);
  else text = dtf.format(d);
  return h("time", { datetime: d.toISOString(), title: utcString(d) }, text);
}

function sameDay(a, b) {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

export function relative(d) {
  const secs = Math.round((Date.now() - d.getTime()) / 1000);
  if (secs < 45) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  const days = Math.round(hrs / 24);
  if (days < 14) return `${days} d ago`;
  return df.format(d);
}

export const dayLabel = (day) => df.format(new Date(day + "T12:00:00Z"));

// ── furniture ──────────────────────────────────────────────────────────────

export function pageHead({ eyebrow, title, lede, meta }) {
  return h("header.page-head",
    eyebrow && h("p.eyebrow", eyebrow),
    h("h1", title),
    lede && h("p.lede", lede),
    meta,
  );
}

export function section(title, { aside, id, note } = {}, ...kids) {
  const hid = id ? `${id}-h` : undefined;
  return h("section.section", { id, "aria-labelledby": hid },
    h("div.section-head", h("h2", { id: hid }, title), aside && h("div.aside", aside)),
    note && h("p.section-note", note),
    ...kids,
  );
}

export function skeleton() {
  return h("div.skel", { "aria-hidden": "true" }, h("i"), h("i"), h("i"), h("i"), h("i"));
}

export function loading(label = "Loading") {
  return h("div", { role: "status", "aria-live": "polite" }, h("span.visually-hidden", label + "…"), skeleton());
}

export function empty(text) {
  return h("p.empty", text);
}

const DC_ORDER = ["public", "internal", "confidential", "restricted"];
export const dcRank = (dc) => DC_ORDER.indexOf(dc);
export const dataClasses = () => DC_ORDER.slice();

export function dcPill(dc) {
  if (!dc) return h("span.muted", "—");
  const known = DC_ORDER.includes(dc);
  return h("span", { class: ["pill", "dc", known && `dc-${dc}`], title: known ? `Data class ${DC_ORDER.indexOf(dc) + 1} of 4` : "Data class" }, dc);
}

export function statusPill(status) {
  return h("span", { class: ["pill", `s-${status}`] }, status || "unknown");
}

export function decisionPill(decision) {
  if (["requested", "reviewed", "approved", "rejected", "retired"].includes(decision)) return statusPill(decision);
  const cls = decision === "n/a" ? "na" : decision;
  return h("span", { class: ["pill", `d-${cls}`] }, decision || "—");
}

export function tags(list, mono = false) {
  if (!list || list.length === 0) return h("span.muted", "—");
  return h("ul.list-inline", list.map((t) => h("li", h(mono ? "span.tag.mono" : "span.tag", t))));
}

export function field(labelText, control, hint) {
  const id = control.id || "f-" + Math.random().toString(36).slice(2, 9);
  control.id = id;
  let hintEl = null;
  if (hint) {
    hintEl = h("p.hint", { id: id + "-hint" }, hint);
    control.setAttribute("aria-describedby", id + "-hint");
  }
  return h("div.field", h("label", { for: id }, labelText), control, hintEl);
}

export function grow(el) {
  el.classList.add("grow");
  return el;
}

export function select(options, value, attrs = {}) {
  return h("select", attrs, options.map((o) => {
    const [v, label] = Array.isArray(o) ? o : [o, o];
    return h("option", { value: v, selected: v === value }, label);
  }));
}

// ── toasts ─────────────────────────────────────────────────────────────────

export function toast(message, kind = "info", title) {
  const box = document.getElementById("toasts");
  if (!box) return;
  const close = h("button", { type: "button", "aria-label": "Dismiss" }, "×");
  const t = h("div", { class: ["toast", kind === "error" && "error"], role: kind === "error" ? "alert" : null },
    h("p", title && h("strong", title + " "), message), close);
  const remove = () => t.remove();
  close.addEventListener("click", remove);
  box.appendChild(t);
  setTimeout(remove, kind === "error" ? 9000 : 4500);
}

export function errorToast(err) {
  toast(err.message || String(err), "error", err.status === 403 ? "Not allowed." : "Something went wrong.");
}

// ── confirm dialog ─────────────────────────────────────────────────────────

export function confirmDialog({ title, body, ok = "Confirm", danger = true }) {
  const dlg = document.getElementById("confirm");
  if (!dlg || typeof dlg.showModal !== "function") return Promise.resolve(window.confirm(`${title}\n\n${body}`));
  replace(document.getElementById("confirm-title"), title);
  replace(document.getElementById("confirm-body"), body);
  const okBtn = document.getElementById("confirm-ok");
  okBtn.textContent = ok;
  okBtn.className = danger ? "button danger" : "button primary";
  dlg.returnValue = "";
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
    dlg.showModal();
    document.getElementById("confirm-cancel").focus();
  });
}

export async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h("textarea", { class: "visually-hidden" });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
  if (button) {
    const prev = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = prev), 1600);
  }
}

// Busy-state helper for buttons that trigger requests.
export async function busy(button, fn) {
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
  }
}

export const icons = {
  chevron: () => s("svg", { viewBox: "0 0 10 10", "aria-hidden": "true", focusable: "false" },
    s("path", { d: "M3 1.5 6.5 5 3 8.5", fill: "none", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round", "stroke-linejoin": "round" })),
  seal: (ok) => s("svg", { viewBox: "0 0 28 28", "aria-hidden": "true", focusable: "false" },
    s("circle", { cx: 14, cy: 14, r: 12, fill: "none", stroke: "currentColor", "stroke-width": "1.5" }),
    s("circle", { cx: 14, cy: 14, r: 8.5, fill: "none", stroke: "currentColor", "stroke-width": "1", "stroke-dasharray": "1.5 2" }),
    ok
      ? s("path", { d: "M9.5 14.3l3 3 6-6.3", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round" })
      : s("path", { d: "M10 10l8 8M18 10l-8 8", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round" })),
  stop: () => s("svg", { viewBox: "0 0 18 18", "aria-hidden": "true", focusable: "false" },
    s("circle", { cx: 9, cy: 9, r: 7.5, fill: "none", stroke: "currentColor", "stroke-width": "1.6" }),
    s("path", { d: "M4 14 14 4", stroke: "currentColor", "stroke-width": "1.6" })),
};

// chainSeal renders an audit.VerifyResult.
export function chainSeal(v) {
  if (!v) return null;
  if (v.ok) {
    return h("div.seal.ok", { role: "status" }, icons.seal(true),
      h("div", h("strong", "VERIFIED"),
        h("span.detail", `${int(v.records)} records, seq ${int(v.first_seq)}–${int(v.last_seq)} · head `),
        h("span.mono", { title: v.head_hash }, shortHash(v.head_hash, 12))));
  }
  const where = v.broken_at ? `at seq ${int(v.broken_at)}` : "";
  return h("div.seal.bad", { role: "alert" }, icons.seal(false),
    h("div", h("strong", `BROKEN ${where}`.trim()), h("span.detail", v.problem || "The hash chain does not verify.")));
}
