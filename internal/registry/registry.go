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

// Package registry governs the lifecycle of models, MCP tools and agents:
// requested → reviewed → approved → retired, with rejection along the way.
//
// Two rules make it worth having. Every transition is written to the audit
// log, and nobody may review or approve their own request (SR 11-7's
// "effective challenge"). Entries declared `approved true` in CDL are seeded
// as approved by the CDL file itself: the merged pull request is the approval.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/store"
)

// Kinds of registry entries.
const (
	KindModel = "model"
	KindTool  = "tool"
	KindAgent = "agent"
)

// Statuses.
const (
	Requested = "requested"
	Reviewed  = "reviewed"
	Approved  = "approved"
	Rejected  = "rejected"
	Retired   = "retired"
)

// Actions that move an entry between statuses.
const (
	ActReview  = "review"
	ActApprove = "approve"
	ActReject  = "reject"
	ActRetire  = "retire"
	ActRequest = "request" // re-request a rejected or retired entry
)

// transitions maps (action, from) → to.
var transitions = map[string]map[string]string{
	ActReview:  {Requested: Reviewed},
	ActApprove: {Reviewed: Approved},
	ActReject:  {Requested: Rejected, Reviewed: Rejected},
	ActRetire:  {Approved: Retired},
	ActRequest: {Rejected: Requested, Retired: Requested},
}

// Errors returned by Transition.
var (
	ErrInvalidTransition = errors.New("invalid transition")
	ErrSeparationOfDuty  = errors.New("separation of duties")
)

// Registry wraps a store and an audit log.
type Registry struct {
	store    store.Store
	log      *audit.Log
	now      func() time.Time
	onChange func()
}

// New returns a registry. onChange (may be nil) is called after every
// successful state change, which is how the gateway config gets re-rendered.
func New(s store.Store, log *audit.Log, onChange func()) *Registry {
	return &Registry{store: s, log: log, now: time.Now, onChange: onChange}
}

// WithClock overrides the clock, for tests.
func (r *Registry) WithClock(now func() time.Time) *Registry { r.now = now; return r }

func (r *Registry) changed() {
	if r.onChange != nil {
		r.onChange()
	}
}

// Seed inserts every model, tool and agent from the estate that the registry
// does not know yet. Existing entries are left alone: once an entry exists,
// its lifecycle belongs to the registry, so a retired model stays retired even
// if the CDL still says `approved true`. Returns the number created.
func (r *Registry) Seed(ctx context.Context, e *estate.Estate) (int, error) {
	actor := e.Source.Actor()
	type item struct {
		kind, name string
		approved   bool
		spec       any
	}
	var items []item
	for _, m := range e.Models {
		items = append(items, item{KindModel, m.Name, m.Approved, m})
	}
	for _, t := range e.Tools {
		items = append(items, item{KindTool, t.Name, t.Approved, t})
	}
	for _, a := range e.Agents {
		items = append(items, item{KindAgent, a.Name, a.Approved, a})
	}
	created := 0
	for _, it := range items {
		spec, _ := json.Marshal(it.spec)
		now := r.now().UTC()
		en := store.Entry{Kind: it.kind, Name: it.name, Status: Requested, Source: "cdl", Spec: spec,
			RequestedBy: actor, CreatedAt: now, UpdatedAt: now, Note: "declared in " + e.Source.File}
		if it.approved {
			en.Status, en.ReviewedBy, en.ApprovedBy = Approved, actor, actor
		}
		ok, err := r.store.PutEntryIfAbsent(ctx, en)
		if err != nil {
			return created, err
		}
		if !ok {
			continue
		}
		created++
		if _, err := r.log.Write(ctx, audit.Record{
			Kind: audit.KindApproval, Actor: actor, Action: "registry.seed", Resource: it.kind + "/" + it.name,
			Decision: en.Status, Reasons: []string{"estate-as-code: declared in " + e.Source.File},
			Details: map[string]any{"cdl_sha256": e.Source.SHA256, "status": en.Status},
		}); err != nil {
			return created, err
		}
	}
	if created > 0 {
		r.changed()
	}
	return created, nil
}

// Request registers a new entry through the API, in status requested.
func (r *Registry) Request(ctx context.Context, kind, name, actor string, spec json.RawMessage, note string) (store.Entry, error) {
	if kind != KindModel && kind != KindTool && kind != KindAgent {
		return store.Entry{}, fmt.Errorf("unknown kind %q", kind)
	}
	if name == "" || actor == "" {
		return store.Entry{}, errors.New("name and actor are required")
	}
	now := r.now().UTC()
	en := store.Entry{Kind: kind, Name: name, Status: Requested, Source: "api", Spec: spec,
		RequestedBy: actor, Note: note, CreatedAt: now, UpdatedAt: now}
	if _, err := r.store.GetEntry(ctx, kind, name); err == nil {
		return store.Entry{}, fmt.Errorf("%s %s already exists: %w", kind, name, store.ErrConflict)
	}
	// Evidence first: if the audit log cannot take the record, nothing changes.
	if _, err := r.log.Write(ctx, audit.Record{Kind: audit.KindApproval, Actor: actor, Action: "registry.request",
		Resource: kind + "/" + name, Decision: Requested, Reasons: nonEmpty(note)}); err != nil {
		return store.Entry{}, fmt.Errorf("audit log unavailable: %w", err)
	}
	ok, err := r.store.PutEntryIfAbsent(ctx, en)
	if err == nil && !ok {
		err = fmt.Errorf("%s %s already exists: %w", kind, name, store.ErrConflict)
	}
	if err != nil {
		r.abandoned(ctx, actor, "request", kind, name, err)
		return store.Entry{}, err
	}
	en.Version = 1
	return en, nil
}

// Transition applies an action to an entry on behalf of actor.
func (r *Registry) Transition(ctx context.Context, kind, name, action, actor, note string) (store.Entry, error) {
	if actor == "" {
		return store.Entry{}, errors.New("actor is required")
	}
	en, err := r.store.GetEntry(ctx, kind, name)
	if err != nil {
		return store.Entry{}, err
	}
	from := en.Status
	to, ok := transitions[action][from]
	if !ok {
		return store.Entry{}, fmt.Errorf("%w: cannot %s a %s %s", ErrInvalidTransition, action, from, kind)
	}
	// Separation of duties. CDL-seeded entries are requested by the CDL file,
	// so a human reviewer is always independent of them.
	if (action == ActReview || action == ActApprove) && sameActor(actor, en.RequestedBy) {
		return store.Entry{}, fmt.Errorf("%w: %s requested %s/%s and cannot %s it", ErrSeparationOfDuty, actor, kind, name, action)
	}
	if action == ActApprove && sameActor(actor, en.ReviewedBy) {
		return store.Entry{}, fmt.Errorf("%w: %s reviewed %s/%s and cannot also approve it", ErrSeparationOfDuty, actor, kind, name)
	}
	en.Status = to
	en.UpdatedAt = r.now().UTC()
	if note != "" {
		en.Note = note
	}
	switch action {
	case ActReview:
		en.ReviewedBy = actor
	case ActApprove:
		en.ApprovedBy = actor
	case ActRequest:
		en.RequestedBy, en.ReviewedBy, en.ApprovedBy = actor, "", ""
	}
	// Evidence first: if the audit log cannot take the record, nothing changes.
	if _, err := r.log.Write(ctx, audit.Record{Kind: audit.KindApproval, Actor: actor, Action: "registry." + action,
		Resource: kind + "/" + name, Decision: to, Reasons: nonEmpty(note),
		Details: map[string]any{"from": from, "to": to}}); err != nil {
		return store.Entry{}, fmt.Errorf("audit log unavailable: %w", err)
	}
	updated, err := r.store.UpdateEntry(ctx, en)
	if err != nil {
		r.abandoned(ctx, actor, action, kind, name, err)
		return store.Entry{}, err
	}
	r.changed()
	return updated, nil
}

// abandoned records that an audited change did not take effect, so the log
// never claims a state the registry does not hold.
func (r *Registry) abandoned(ctx context.Context, actor, action, kind, name string, cause error) {
	r.log.Write(ctx, audit.Record{Kind: audit.KindApproval, Actor: actor, Action: "registry." + action + ".abandoned", //nolint:errcheck
		Resource: kind + "/" + name, Decision: audit.Error, Reasons: []string{cause.Error()}})
}

// sameActor compares identities the way people write them.
func sameActor(a, b string) bool {
	return a != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// List returns entries of a kind ("" for all).
func (r *Registry) List(ctx context.Context, kind string) ([]store.Entry, error) {
	return r.store.ListEntries(ctx, kind)
}

// Get returns one entry.
func (r *Registry) Get(ctx context.Context, kind, name string) (store.Entry, error) {
	return r.store.GetEntry(ctx, kind, name)
}

// Approvals is the live approval state, by kind and name.
type Approvals struct {
	Models, Tools, Agents map[string]bool
}

// Approvals reads the current approval state of every entry.
func (r *Registry) Approvals(ctx context.Context) (Approvals, error) {
	es, err := r.store.ListEntries(ctx, "")
	if err != nil {
		return Approvals{}, err
	}
	a := Approvals{Models: map[string]bool{}, Tools: map[string]bool{}, Agents: map[string]bool{}}
	for _, e := range es {
		ok := e.Status == Approved
		switch e.Kind {
		case KindModel:
			a.Models[e.Name] = ok
		case KindTool:
			a.Tools[e.Name] = ok
		case KindAgent:
			a.Agents[e.Name] = ok
		}
	}
	return a, nil
}

// Pending returns entries waiting on a human: requested or reviewed.
func (r *Registry) Pending(ctx context.Context) ([]store.Entry, error) {
	es, err := r.store.ListEntries(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []store.Entry
	for _, e := range es {
		if e.Status == Requested || e.Status == Reviewed {
			out = append(out, e)
		}
	}
	return out, nil
}

// MergeAPIModels returns a copy of the estate with models that were requested
// through the API (and so are absent from the CDL) appended. Teams still need
// a CDL change to be entitled to them: the registry governs what exists, the
// estate governs who may use it.
func MergeAPIModels(e *estate.Estate, entries []store.Entry) *estate.Estate {
	c := *e
	c.Models = append([]estate.Model(nil), e.Models...)
	for _, en := range entries {
		if en.Kind != KindModel || en.Source != "api" {
			continue
		}
		if _, exists := c.Model(en.Name); exists {
			continue
		}
		var m estate.Model
		if json.Unmarshal(en.Spec, &m) != nil {
			continue
		}
		m.Name = en.Name
		if m.UpstreamID == "" {
			m.UpstreamID = en.Name
		}
		if !m.DataClass.Valid() {
			m.DataClass = estate.Internal
		}
		if _, ok := c.Provider(m.Provider); !ok {
			continue // cannot route a model whose provider the estate doesn't declare
		}
		c.Models = append(c.Models, m)
	}
	c.Sort()
	return &c
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
