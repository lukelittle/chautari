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

// Package store persists Chautari's state: the registry, API keys, spend and
// the audit log. Postgres backs real deployments; Memory backs unit tests and
// `chautari serve --dev`. Both satisfy the same contract test suite.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
)

// ErrNotFound is returned when a lookup finds nothing.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned on optimistic-lock or uniqueness failures.
var ErrConflict = errors.New("conflict")

// Entry is a registry record for a model, tool or agent.
type Entry struct {
	Kind        string          `json:"kind"` // model | tool | agent
	Name        string          `json:"name"`
	Status      string          `json:"status"`
	Source      string          `json:"source"` // "cdl" or "api"
	Spec        json.RawMessage `json:"spec"`   // the estate object, as JSON
	RequestedBy string          `json:"requested_by"`
	ReviewedBy  string          `json:"reviewed_by,omitempty"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
	Note        string          `json:"note,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Version     int64           `json:"version"`
}

// Key is an API key. Only its SHA-256 hash is stored.
type Key struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"` // first characters, for display
	Hash      string     `json:"-"`
	Name      string     `json:"name"`
	App       string     `json:"app"`
	Team      string     `json:"team"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Active reports whether the key may be used.
func (k Key) Active() bool { return k.RevokedAt == nil }

// SpendKey identifies one spend bucket: who, over which calendar window.
type SpendKey struct {
	Scope       string    `json:"scope"`   // team | app | key
	Subject     string    `json:"subject"` // team name, app name or key id
	Period      string    `json:"period"`  // day | week | month
	WindowStart time.Time `json:"window_start"`
}

// Spend is the accumulated usage in one bucket.
type Spend struct {
	SpendKey
	USD      float64 `json:"usd"`
	Tokens   int64   `json:"tokens"`
	Requests int64   `json:"requests"`
}

// Store is the persistence contract.
type Store interface {
	audit.Appender

	// Registry
	PutEntryIfAbsent(ctx context.Context, e Entry) (created bool, err error)
	GetEntry(ctx context.Context, kind, name string) (Entry, error)
	ListEntries(ctx context.Context, kind string) ([]Entry, error)
	// UpdateEntry writes e if the stored version equals e.Version, and
	// increments the version. Otherwise it returns ErrConflict.
	UpdateEntry(ctx context.Context, e Entry) (Entry, error)

	// Keys
	CreateKey(ctx context.Context, k Key) error
	KeyByHash(ctx context.Context, hash string) (Key, error)
	ListKeys(ctx context.Context) ([]Key, error)
	RevokeKey(ctx context.Context, id string, at time.Time) (Key, error)

	// Spend
	AddSpend(ctx context.Context, keys []SpendKey, usd float64, tokens int64) error
	GetSpend(ctx context.Context, k SpendKey) (Spend, error)
	ListSpend(ctx context.Context, scope, period string, since time.Time) ([]Spend, error)

	// Audit
	ListAudit(ctx context.Context, q audit.Query) ([]audit.Record, error)
	AuditHead(ctx context.Context) (seq int64, hash string, err error)

	Close()
}
