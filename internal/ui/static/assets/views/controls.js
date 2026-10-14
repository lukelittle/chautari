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

// Controls: the evidence-backed mapping to NIST AI RMF and SR 11-7.

import { get } from "../api.js";
import { h, time, shortHash, pageHead, section, empty } from "../dom.js";

export default async function controls(page) {
  const rep = await get("/api/reports/controls");

  page.append(pageHead({
    eyebrow: "Controls",
    title: "What we can show an examiner",
    lede: "Chautari's technical controls mapped to NIST AI RMF 1.0 outcomes and to SR 11-7 model risk guidance, with live evidence quoted from the registry and the audit log. It supports, and does not replace, your control owners' assessment.",
    meta: h("div.meta-line",
      h("span", h("b", "Estate "), rep.estate),
      h("span", h("b", "CDL "), h("span.mono", { title: rep.cdl_sha256 }, shortHash(rep.cdl_sha256))),
      rep.live ? h("span", h("b", "Evidence as of "), time(rep.generated_at)) : h("span", "static report")),
  }));

  page.append(h("div.buttons.toolbar",
    h("a.button.primary", { href: "/api/reports/controls?format=html", target: "_blank", rel: "noopener" }, "Open printable report ↗"),
    h("a.button", { href: "/api/reports/controls?format=md", download: "controls-report.md" }, "Download Markdown"),
    h("a.button.quiet", { href: "/api/reports/controls", target: "_blank", rel: "noopener" }, "JSON")));

  const list = rep.controls || [];
  page.append(section("Controls", { id: "controls", aside: `${list.filter((c) => c.status === "in place").length} of ${list.length} in place` },
    list.length ? h("ol.controls-list", list.map((c) => {
      const nist = c.refs.filter((r) => r.framework.startsWith("NIST"));
      const sr = c.refs.filter((r) => !r.framework.startsWith("NIST"));
      return h("li.control",
        h("div.control-id", c.id),
        h("div",
          h("h3", c.title),
          h("div.refs",
            nist.map((r) => h("span.tag", { title: r.text }, r.id)),
            sr.map((r) => h("span.tag", { title: `${r.framework}: ${r.text}` }, "SR 11-7 · " + r.id.split(": ").pop()))),
          c.evidence && c.evidence.length ? h("ul.evidence", c.evidence.map((x) => h("li", x))) : null,
          h("details",
            h("summary", "How it works"),
            h("p", c.description),
            h("p", h("b", "Implemented by "), h("code", c.mechanism)),
            c.config && c.config.length ? h("ul.evidence", c.config.map((x) => h("li", x))) : null)),
        h("div", h("span", { class: ["pill", c.status === "in place" ? "ok" : "bad"] }, c.status)));
    })) : empty("The report has no controls.")));
}
