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

package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
)

// Memory is an in-process Store. It is safe for concurrent use and loses
// everything on restart, which is exactly what tests and --dev want.
type Memory struct {
	mu      sync.Mutex
	entries map[string]Entry // kind/name
	keys    map[string]Key   // id
	byHash  map[string]string
	spend   map[SpendKey]Spend
	log     []audit.Record
	// failAudit, when set, makes every audit append fail (tests only).
	failAudit error
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		entries: map[string]Entry{},
		keys:    map[string]Key{},
		byHash:  map[string]string{},
		spend:   map[SpendKey]Spend{},
	}
}

func entryID(kind, name string) string { return kind + "/" + name }

func (m *Memory) PutEntryIfAbsent(_ context.Context, e Entry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := entryID(e.Kind, e.Name)
	if _, ok := m.entries[id]; ok {
		return false, nil
	}
	e.Version = 1
	m.entries[id] = e
	return true, nil
}

func (m *Memory) GetEntry(_ context.Context, kind, name string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[entryID(kind, name)]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return e, nil
}

func (m *Memory) ListEntries(_ context.Context, kind string) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for _, e := range m.entries {
		if kind == "" || e.Kind == kind {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (m *Memory) UpdateEntry(_ context.Context, e Entry) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := entryID(e.Kind, e.Name)
	cur, ok := m.entries[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	if cur.Version != e.Version {
		return Entry{}, ErrConflict
	}
	e.Version++
	m.entries[id] = e
	return e, nil
}

func (m *Memory) CreateKey(_ context.Context, k Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.keys[k.ID]; dup {
		return ErrConflict
	}
	if _, dup := m.byHash[k.Hash]; dup {
		return ErrConflict
	}
	m.keys[k.ID] = k
	m.byHash[k.Hash] = k.ID
	return nil
}

func (m *Memory) KeyByHash(_ context.Context, hash string) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byHash[hash]
	if !ok {
		return Key{}, ErrNotFound
	}
	return m.keys[id], nil
}

func (m *Memory) ListKeys(context.Context) ([]Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Key, 0, len(m.keys))
	for _, k := range m.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *Memory) RevokeKey(_ context.Context, id string, at time.Time) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return Key{}, ErrNotFound
	}
	if k.RevokedAt == nil {
		t := at.UTC()
		k.RevokedAt = &t
		m.keys[id] = k
	}
	return k, nil
}

func (m *Memory) AddSpend(_ context.Context, keys []SpendKey, usd float64, tokens int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		k.WindowStart = k.WindowStart.UTC()
		s := m.spend[k]
		s.SpendKey = k
		s.USD += usd
		s.Tokens += tokens
		s.Requests++
		m.spend[k] = s
	}
	return nil
}

func (m *Memory) GetSpend(_ context.Context, k SpendKey) (Spend, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k.WindowStart = k.WindowStart.UTC()
	s, ok := m.spend[k]
	if !ok {
		return Spend{SpendKey: k}, nil
	}
	return s, nil
}

func (m *Memory) ListSpend(_ context.Context, scope, period string, since time.Time) ([]Spend, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Spend
	for k, s := range m.spend {
		if (scope == "" || k.Scope == scope) && (period == "" || k.Period == period) && !k.WindowStart.Before(since) {
			out = append(out, s)
		}
	}
	sortSpend(out)
	return out, nil
}

func sortSpend(out []Spend) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.WindowStart.Equal(b.WindowStart) {
			return a.WindowStart.Before(b.WindowStart)
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Period < b.Period
	})
}

func (m *Memory) AppendAudit(_ context.Context, seal func(audit.Head) audit.Record) (audit.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := audit.Head{Hash: audit.GenesisHash}
	if n := len(m.log); n > 0 {
		h = audit.Head{Seq: m.log[n-1].Seq, Hash: m.log[n-1].Hash, Time: m.log[n-1].Time}
	}
	if m.failAudit != nil {
		return audit.Record{}, m.failAudit
	}
	r := seal(h)
	m.log = append(m.log, r)
	return r, nil
}

func (m *Memory) ListAudit(_ context.Context, q audit.Query) ([]audit.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Record
	if q.Desc {
		for i := len(m.log) - 1; i >= 0; i-- {
			if q.Match(m.log[i]) {
				out = append(out, m.log[i])
				if q.Limit > 0 && len(out) == q.Limit {
					break
				}
			}
		}
		return out, nil
	}
	for _, r := range m.log {
		if q.Match(r) {
			out = append(out, r)
			if q.Limit > 0 && len(out) == q.Limit {
				break
			}
		}
	}
	return out, nil
}

func (m *Memory) AuditHead(context.Context) (int64, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := len(m.log); n > 0 {
		return m.log[n-1].Seq, m.log[n-1].Hash, nil
	}
	return 0, audit.GenesisHash, nil
}

// Tamper replaces a stored audit record without re-sealing it. It exists so
// tests can prove verification catches tampering; nothing else may call it.
func (m *Memory) Tamper(seq int64, f func(*audit.Record)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.log {
		if m.log[i].Seq == seq {
			f(&m.log[i])
		}
	}
}

// FailAudit makes subsequent audit appends fail with err (nil restores).
// It exists so tests can prove the server fails closed without an audit log.
func (m *Memory) FailAudit(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAudit = err
}

func (m *Memory) Close() {}
