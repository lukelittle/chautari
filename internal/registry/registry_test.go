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

package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/store"
)

func setup(t *testing.T) (*Registry, *store.Memory, *int) {
	t.Helper()
	s := store.NewMemory()
	changes := 0
	r := New(s, audit.NewLog(s), func() { changes++ })
	e, err := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	n, err := r.Seed(context.Background(), e)
	if err != nil || n != 7 {
		t.Fatalf("seed: %d %v", n, err)
	}
	return r, s, &changes
}

func TestSeedFromCDL(t *testing.T) {
	r, s, changes := setup(t)
	ctx := context.Background()
	a, _ := r.Approvals(ctx)
	if !a.Models["claude-sonnet"] || a.Models["llama-70b"] || !a.Tools["jira-mcp"] || a.Tools["core-banking-mcp"] || !a.Agents["underwriting-agent"] {
		t.Fatalf("approvals = %+v", a)
	}
	en, _ := r.Get(ctx, KindModel, "claude-sonnet")
	if en.ApprovedBy == "" || en.ApprovedBy[:4] != "cdl:" {
		t.Fatalf("approved by = %q", en.ApprovedBy)
	}
	recs, _ := s.ListAudit(ctx, audit.Query{Kind: audit.KindApproval})
	if len(recs) != 7 {
		t.Fatalf("audit records = %d", len(recs))
	}
	if *changes != 1 {
		t.Fatalf("onChange calls = %d", *changes)
	}
	// Re-seeding is a no-op.
	e, _ := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	if n, _ := r.Seed(ctx, e); n != 0 {
		t.Fatalf("reseed created %d", n)
	}
	pending, _ := r.Pending(ctx)
	if len(pending) != 2 {
		t.Fatalf("pending = %d", len(pending))
	}
}

func TestLifecycleWithSeparationOfDuties(t *testing.T) {
	r, s, _ := setup(t)
	ctx := context.Background()
	_, err := r.Request(ctx, KindModel, "mistral-large", "alice", []byte(`{"provider":"mock","upstream_id":"mistral-large"}`), "for summarisation")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Request(ctx, KindModel, "mistral-large", "alice", nil, ""); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate request: %v", err)
	}
	if _, err := r.Transition(ctx, KindModel, "mistral-large", ActReview, "alice", ""); !errors.Is(err, ErrSeparationOfDuty) {
		t.Fatalf("self-review: %v", err)
	}
	if _, err := r.Transition(ctx, KindModel, "mistral-large", ActApprove, "bob", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approve before review: %v", err)
	}
	if _, err := r.Transition(ctx, KindModel, "mistral-large", ActReview, "bob", "validated on holdout set"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Transition(ctx, KindModel, "mistral-large", ActApprove, "bob", ""); !errors.Is(err, ErrSeparationOfDuty) {
		t.Fatalf("reviewer approving: %v", err)
	}
	en, err := r.Transition(ctx, KindModel, "mistral-large", ActApprove, "carol", "")
	if err != nil || en.Status != Approved || en.ApprovedBy != "carol" || en.ReviewedBy != "bob" {
		t.Fatalf("approve: %+v %v", en, err)
	}
	en, err = r.Transition(ctx, KindModel, "mistral-large", ActRetire, "dave", "superseded")
	if err != nil || en.Status != Retired {
		t.Fatalf("retire: %+v %v", en, err)
	}
	en, err = r.Transition(ctx, KindModel, "mistral-large", ActRequest, "alice", "bring it back")
	if err != nil || en.Status != Requested || en.ReviewedBy != "" {
		t.Fatalf("re-request: %+v %v", en, err)
	}
	recs, _ := s.ListAudit(ctx, audit.Query{Kind: audit.KindApproval})
	// 7 seeds + request + review + approve + retire + re-request
	if len(recs) != 12 || recs[len(recs)-2].Decision != Retired {
		t.Fatalf("audit = %d records", len(recs))
	}
	if res := audit.Verify(recs); !res.OK {
		// Filtering by kind leaves gaps only if other kinds were written; here
		// only approvals exist, so the chain must be complete.
		t.Fatalf("chain: %+v", res)
	}
}

func TestCDLEntriesNeedHumanReviewAndRetireIsKillSwitch(t *testing.T) {
	r, _, _ := setup(t)
	ctx := context.Background()
	// llama-70b was requested by the CDL file; any human may review it.
	if _, err := r.Transition(ctx, KindModel, "llama-70b", ActReview, "model-risk@bank", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Transition(ctx, KindModel, "claude-sonnet", ActRetire, "ciso@bank", "incident 4411"); err != nil {
		t.Fatal(err)
	}
	a, _ := r.Approvals(ctx)
	if a.Models["claude-sonnet"] {
		t.Fatal("retired model must not be approved")
	}
	if _, err := r.Transition(ctx, KindModel, "claude-sonnet", ActApprove, "x", ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("approve retired: %v", err)
	}
}

func TestMergeAPIModels(t *testing.T) {
	r, s, _ := setup(t)
	ctx := context.Background()
	r.Request(ctx, KindModel, "mistral-large", "alice", []byte(`{"provider":"mock","upstream_id":"mistral-large-2","data_class":"public"}`), "")
	r.Request(ctx, KindModel, "orphan", "alice", []byte(`{"provider":"nope"}`), "")
	e, _ := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	entries, _ := s.ListEntries(ctx, "")
	merged := MergeAPIModels(e, entries)
	m, ok := merged.Model("mistral-large")
	if !ok || m.UpstreamID != "mistral-large-2" || m.DataClass != "public" {
		t.Fatalf("merged = %+v %v", m, ok)
	}
	if _, ok := merged.Model("orphan"); ok {
		t.Fatal("model with unknown provider must not merge")
	}
	if len(e.Models) != 4 {
		t.Fatal("merge must not mutate the original estate")
	}
}

func TestSeparationOfDutiesIgnoresCaseAndSpace(t *testing.T) {
	r, _, _ := setup(t)
	ctx := context.Background()
	r.Request(ctx, KindModel, "m2", "mallory@bank", []byte(`{"provider":"mock"}`), "")
	if _, err := r.Transition(ctx, KindModel, "m2", ActReview, " Mallory@Bank ", ""); !errors.Is(err, ErrSeparationOfDuty) {
		t.Fatalf("case-variant self-review: %v", err)
	}
	r.Transition(ctx, KindModel, "m2", ActReview, "bob@bank", "")
	if _, err := r.Transition(ctx, KindModel, "m2", ActApprove, "BOB@bank", ""); !errors.Is(err, ErrSeparationOfDuty) {
		t.Fatalf("case-variant reviewer approving: %v", err)
	}
}

// Regression: a transition used to be stored before its audit record, so an
// audit failure left an approval with no evidence.
func TestNoStateChangeWithoutEvidence(t *testing.T) {
	r, s, _ := setup(t)
	ctx := context.Background()
	s.FailAudit(errors.New("disk full"))
	if _, err := r.Transition(ctx, KindModel, "claude-sonnet", ActRetire, "ciso@bank", ""); err == nil {
		t.Fatal("transition must fail when the audit log is unavailable")
	}
	if _, err := r.Request(ctx, KindModel, "m3", "alice", []byte(`{}`), ""); err == nil {
		t.Fatal("request must fail when the audit log is unavailable")
	}
	s.FailAudit(nil)
	en, _ := r.Get(ctx, KindModel, "claude-sonnet")
	if en.Status != Approved {
		t.Fatalf("state changed without an audit record: %s", en.Status)
	}
	if _, err := r.Get(ctx, KindModel, "m3"); err == nil {
		t.Fatal("entry created without an audit record")
	}
}
