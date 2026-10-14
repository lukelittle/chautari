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

// chart.js: one hand-drawn chart, a stacked column chart of spend by day.
// Rendered at the container's real pixel width so type stays legible.

import { h, s, clear, usd, dayLabel } from "./dom.js";

const SERIES = 5; // categorical slots s1..s5, assigned in fixed order

function niceStep(max, ticks) {
  const raw = max / ticks;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  const step = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
  return step * mag;
}

function roundedTop(x, y, w, ht, r) {
  r = Math.min(r, w / 2, ht);
  return `M${x},${y + ht}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + ht}Z`;
}

function axisMoney(v, step) {
  if (v === 0) return "$0";
  if (step >= 1000) return "$" + (v / 1000).toFixed(step % 1000 ? 1 : 0) + "k";
  let d = 0;
  while (d < 6 && Math.abs(Math.round(step * 10 ** d) - step * 10 ** d) > 1e-9) d++;
  return "$" + v.toFixed(d);
}

// lastDays returns n ISO dates (UTC) ending today.
export function lastDays(n, end = new Date()) {
  const out = [];
  const base = Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate());
  for (let i = n - 1; i >= 0; i--) out.push(new Date(base - i * 86400000).toISOString().slice(0, 10));
  return out;
}

// colourFor keeps colour attached to the entity, not its rank: the series
// list passed in should be in a stable order (e.g. estate order).
export function seriesClass(i) {
  return `s${(i % SERIES) + 1}`;
}

/**
 * stackedColumns renders spend by day.
 * @param {object} o
 * @param {string[]} o.days ISO dates
 * @param {{key:string,label:string,cls:string,values:Map<string,number>}[]} o.series
 * @param {string} o.title accessible name
 */
export function stackedColumns({ days, series, title, height = 220 }) {
  const wrap = h("figure.chart-figure");
  const totals = new Map(series.map((sr) => [sr.key, [...sr.values.values()].reduce((a, b) => a + b, 0)]));
  const legend = h("ul.legend", { "aria-label": "Series" },
    series.map((sr) => h("li", h("span", { class: ["swatch", sr.cls], "aria-hidden": "true" }), sr.label,
      h("span.total", usd(totals.get(sr.key))))));
  const box = h("div.chart");
  const tip = h("div.tooltip", { hidden: true, "aria-hidden": "true" });
  box.appendChild(tip);

  const draw = () => {
    const width = Math.max(280, Math.floor(box.clientWidth || 640));
    for (const old of box.querySelectorAll("svg")) old.remove();
    const m = { top: 12, right: 4, bottom: 26, left: 46 };
    const pw = width - m.left - m.right;
    const ph = height - m.top - m.bottom;
    const dayTotal = days.map((d) => series.reduce((a, sr) => a + (sr.values.get(d) || 0), 0));
    const max = Math.max(...dayTotal, 0);
    const step = max > 0 ? niceStep(max, 4) : 1;
    const top = max > 0 ? Math.ceil(max / step) * step : 4;
    const y = (v) => m.top + ph - (v / top) * ph;
    const slot = pw / days.length;
    const bw = Math.max(3, Math.min(30, slot * 0.6));

    const svg = s("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": title });
    const grid = s("g", { class: "grid" });
    for (let v = 0; v <= top + 1e-9; v += step) {
      const yy = Math.round(y(v)) + 0.5;
      grid.appendChild(s("line", { x1: m.left, x2: width - m.right, y1: yy, y2: yy, class: v === 0 ? "base" : null }));
      grid.appendChild(s("text", { x: m.left - 8, y: yy + 3.5, "text-anchor": "end" }, max > 0 ? axisMoney(v, step) : v === 0 ? "$0" : ""));
    }
    svg.appendChild(grid);

    const every = Math.max(1, Math.ceil(48 / slot));
    days.forEach((d, i) => {
      const cx = m.left + slot * i + slot / 2;
      const x = cx - bw / 2;
      const col = s("g", { class: "col", tabindex: 0, role: "img",
        "aria-label": `${dayLabel(d)}: ${usd(dayTotal[i])}` + series.filter((sr) => sr.values.get(d)).map((sr) => `, ${sr.label} ${usd(sr.values.get(d))}`).join("") });
      col.appendChild(s("rect", { class: "slot", x: m.left + slot * i + 1, y: m.top, width: Math.max(1, slot - 2), height: ph, rx: 3 }));
      let acc = 0;
      const present = series.filter((sr) => (sr.values.get(d) || 0) > 0);
      if (present.length === 0) {
        col.appendChild(s("rect", { class: "empty-tick", x: cx - 1.5, y: y(0) - 2, width: 3, height: 2 }));
      }
      present.forEach((sr, k) => {
        const v = sr.values.get(d);
        const y0 = y(acc);
        const y1 = y(acc + v);
        acc += v;
        const gap = k > 0 ? 2 : 0; // a 2px surface gap between stacked segments
        const segH = Math.max(1, y0 - y1 - gap);
        const isTop = k === present.length - 1;
        if (isTop) col.appendChild(s("path", { class: sr.cls, d: roundedTop(x, y0 - gap - segH, bw, segH, 3) }));
        else col.appendChild(s("rect", { class: sr.cls, x, y: y0 - gap - segH, width: bw, height: segH }));
      });
      if (i % every === (days.length - 1) % every) {
        col.appendChild(s("text", { x: cx, y: height - 8, "text-anchor": "middle" }, dayLabel(d)));
      }
      const show = () => {
        clear(tip);
        tip.appendChild(h("h4", dayLabel(d)));
        const dl = h("dl");
        for (const sr of series) {
          const v = sr.values.get(d) || 0;
          if (!v) continue;
          dl.append(h("dt", h("span", { class: ["swatch", sr.cls] }), h("span", sr.label)), h("dd", usd(v, { precise: true })));
        }
        if (!dl.firstChild) dl.append(h("dt", h("span"), h("span", "No spend")), h("dd", ""));
        tip.append(dl, h("div.tt-total", h("span", "Total"), h("span", usd(dayTotal[i], { precise: true }))));
        tip.hidden = false;
        const left = Math.min(Math.max(cx, 90), width - 90);
        tip.style.left = `${left}px`;
        tip.style.top = `${Math.max(y(dayTotal[i]), m.top + 40)}px`;
      };
      const hide = () => (tip.hidden = true);
      col.addEventListener("mouseenter", show);
      col.addEventListener("focus", show);
      col.addEventListener("mouseleave", hide);
      col.addEventListener("blur", hide);
      svg.appendChild(col);
    });
    box.insertBefore(svg, tip);
  };

  // Table view: identity is never colour alone.
  const table = h("table.table",
    h("caption.visually-hidden", title),
    h("thead", h("tr", h("th", { scope: "col" }, "Day"), series.map((sr) => h("th.num", { scope: "col" }, sr.label)), h("th.num", { scope: "col" }, "Total"))),
    h("tbody", days.slice().reverse().filter((d) => series.some((sr) => sr.values.get(d))).map((d) =>
      h("tr", h("td.nowrap", dayLabel(d)), series.map((sr) => h("td.num", sr.values.get(d) ? usd(sr.values.get(d), { precise: true }) : "—")),
        h("td.num", usd(series.reduce((a, sr) => a + (sr.values.get(d) || 0), 0), { precise: true }))))));
  const details = h("details.data-table", h("summary", "Show as a table"), h("div.table-wrap", table));

  wrap.append(legend, box, details);
  let raf = 0;
  const ro = new ResizeObserver(() => {
    if (!box.isConnected && wrap.dataset.drawn) return ro.disconnect();
    wrap.dataset.drawn = "1";
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(draw);
  });
  ro.observe(box);
  requestAnimationFrame(draw);
  return wrap;
}

// seriesFromSpend groups rows of {day|window_start, subject|team, usd}.
export function seriesFromRows(rows, order, keyOf, dayOf) {
  const names = [...new Set([...order, ...rows.map(keyOf)])].filter((n) => rows.some((r) => keyOf(r) === n));
  return names.map((name) => {
    const values = new Map();
    for (const r of rows) if (keyOf(r) === name) values.set(dayOf(r), (values.get(dayOf(r)) || 0) + r.usd);
    // Colour follows position in the stable estate order, not in this filtered list.
    const idx = order.indexOf(name);
    return { key: name, label: name, cls: seriesClass(idx >= 0 ? idx : order.length + names.indexOf(name)), values };
  });
}
