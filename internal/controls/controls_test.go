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

package controls

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/lukelittle/chautari/internal/cdl"
)

func TestStaticReport(t *testing.T) {
	e, err := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	r := Build(e, nil)
	if r.Live || len(r.Controls) != 10 {
		t.Fatalf("report = %+v", r)
	}
	seen := map[string]bool{}
	for _, c := range r.Controls {
		if seen[c.ID] {
			t.Fatalf("duplicate control %s", c.ID)
		}
		seen[c.ID] = true
		if len(c.Refs) == 0 || c.Description == "" || c.Mechanism == "" {
			t.Errorf("%s is incomplete", c.ID)
		}
		hasNIST, hasSR := false, false
		for _, ref := range c.Refs {
			hasNIST = hasNIST || ref.Framework == NIST
			hasSR = hasSR || ref.Framework == SR117
		}
		if !hasNIST {
			t.Errorf("%s has no NIST AI RMF mapping", c.ID)
		}
		_ = hasSR
	}
	md := string(Markdown(r))
	for _, want := range []string{"# AI Controls Report: Himalayan Bank", "MANAGE 2.4", "model inventory", "team lending: 2000.00 USD/month", "policy pii (all teams): redact inbound aws-key,card,email,iban,phone,ssn; block outbound card,ssn"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if !bytes.Equal(Markdown(r), Markdown(Build(e, nil))) {
		t.Fatal("static report must be deterministic (it is generated into repos)")
	}
}

func TestLiveEvidence(t *testing.T) {
	e, _ := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	ev := &Evidence{GeneratedAt: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), ChainOK: false, ChainChecked: 41, AuditRecords: 42,
		AuditByDecision: map[string]int{"allow": 30, "deny": 5, "block": 4, "redact": 3},
		RegistryCounts:  map[string]map[string]int{"model": {"approved": 3, "retired": 1}}}
	r := Build(e, ev)
	md := string(Markdown(r))
	for _, want := range []string{"chain BROKEN", "4 blocked, 3 redacted", "30 requests allowed, 5 denied", "1 entries currently retired"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q", want)
		}
	}
	h, err := HTML(r)
	if err != nil || !bytes.Contains(h, []byte("<title>AI Controls Report: Himalayan Bank</title>")) {
		t.Fatalf("html: %v", err)
	}
}

// sr117Sections are the SR 11-7 (Fed/OCC, April 2011) sections and topics the
// catalogue may cite, as "Section: topic". Check the guidance before adding
// one, so the report never cites a section that does not exist.
var sr117Sections = map[string]bool{
	"Overview of Model Risk Management: effective challenge":         true,
	"Model Validation: independence":                                 true,
	"Model Validation: ongoing monitoring":                           true,
	"Model Validation: vendor and other third-party products":        true,
	"Governance, Policies, and Controls: model inventory":            true,
	"Governance, Policies, and Controls: policies and procedures":    true,
	"Governance, Policies, and Controls: roles and responsibilities": true,
	"Governance, Policies, and Controls: documentation":              true,
	"Governance, Policies, and Controls: internal audit":             true,
}

func TestSR117RefsCiteKnownSections(t *testing.T) {
	e, _ := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	for _, c := range Build(e, &Evidence{}).Controls {
		for _, ref := range c.Refs {
			if ref.Framework == SR117 && !sr117Sections[ref.ID] {
				t.Errorf("%s cites unknown SR 11-7 section %q", c.ID, ref.ID)
			}
		}
	}
}

func status(r Report, id string) Control {
	for _, c := range r.Controls {
		if c.ID == id {
			return c
		}
	}
	return Control{}
}

func TestStatusReflectsLiveEvidence(t *testing.T) {
	e, _ := cdl.LoadFile("../../examples/himalayan-bank.cdl")

	static := Build(e, nil)
	if s := status(static, "CH-02").Status; s != "in place" {
		t.Fatalf("static CH-02 = %q", s)
	}
	if d := status(static, "CH-02").Description; !strings.Contains(d, "per-person admin tokens") {
		t.Fatalf("CH-02 description = %q", d)
	}
	if d := status(static, "CH-07").Description; !strings.Contains(d, "immediately on the replica that handles the request") || !strings.Contains(d, "within one resync interval (15 s by default)") {
		t.Fatalf("CH-07 description = %q", d)
	}

	broken := Build(e, &Evidence{ChainOK: false})
	ch06, ch02 := status(broken, "CH-06"), status(broken, "CH-02")
	if ch06.Status != "attention: chain broken" {
		t.Fatalf("CH-06 with a broken chain = %q", ch06.Status)
	}
	if ch02.Status != "partial: approvers self-declared" || !strings.Contains(strings.Join(ch02.Evidence, "\n"),
		"Admin access uses a shared token; approver names are self-declared, so separation of duties is advisory. Configure per-person admin tokens (CHAUTARI_ADMIN_TOKENS) to enforce it.") {
		t.Fatalf("CH-02 without verified actors = %+v", ch02)
	}
	h, _ := HTML(broken)
	if !bytes.Contains(h, []byte(`<td class="no">attention: chain broken</td>`)) {
		t.Fatal("a broken chain must render red")
	}

	good := Build(e, &Evidence{ChainOK: true, ActorsVerified: true})
	ch06, ch02 = status(good, "CH-06"), status(good, "CH-02")
	if ch06.Status != "in place" || ch02.Status != "in place" {
		t.Fatalf("statuses = %q, %q", ch06.Status, ch02.Status)
	}
	if !strings.Contains(strings.Join(ch02.Evidence, "\n"), "Approver identities are bound to per-person admin tokens.") {
		t.Fatalf("CH-02 evidence = %q", ch02.Evidence)
	}
}

func TestSR117Citations(t *testing.T) {
	e, _ := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	md := string(Markdown(Build(e, nil)))
	for _, want := range []string{
		"SR 11-7, Model Validation: vendor and other third-party products: Vendor products should be incorporated into a bank's broader model risk management framework following the same principles as applied to in-house models.",
		"SR 11-7, Overview of Model Risk Management: effective challenge: Effective challenge depends on a combination of incentives, competence, and influence.",
		"SR 11-7, Model Validation: independence: Validation involves a degree of independence from model development and use.",
		"SR 11-7, Governance, Policies, and Controls: internal audit: Internal audit should assess the overall effectiveness of the model risk management framework and verify that records of model use and validation are kept.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}
