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
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lukelittle/chautari/internal/audit"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Advisory lock ids. Arbitrary but fixed.
const (
	lockMigrate = 0x63686175 // "chau"
	lockAudit   = 0x74617269 // "tari"
)

// Postgres is the production Store.
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects, waits for the database (up to wait), and applies
// migrations under an advisory lock so concurrent replicas are safe.
func OpenPostgres(ctx context.Context, url string, wait time.Duration) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err = pool.Ping(ctx)
		if err == nil || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres unreachable: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) migrate(ctx context.Context) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockMigrate); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockMigrate) //nolint:errcheck
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, n).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, _ := migrations.ReadFile(n)
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, n); err != nil {
			tx.Rollback(ctx) //nolint:errcheck
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close releases the pool.
func (p *Postgres) Close() { p.pool.Close() }

// Ping checks connectivity, for readiness probes.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// ── registry ────────────────────────────────────────────────────────────────

const entryCols = `kind, name, status, source, spec, requested_by, reviewed_by, approved_by, note, created_at, updated_at, version`

func scanEntry(row pgx.Row) (Entry, error) {
	var e Entry
	var spec []byte
	err := row.Scan(&e.Kind, &e.Name, &e.Status, &e.Source, &spec, &e.RequestedBy, &e.ReviewedBy, &e.ApprovedBy, &e.Note, &e.CreatedAt, &e.UpdatedAt, &e.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	e.Spec = json.RawMessage(spec)
	e.CreatedAt, e.UpdatedAt = e.CreatedAt.UTC(), e.UpdatedAt.UTC()
	return e, err
}

func specOrEmpty(s json.RawMessage) []byte {
	if len(s) == 0 {
		return []byte("{}")
	}
	return s
}

func (p *Postgres) PutEntryIfAbsent(ctx context.Context, e Entry) (bool, error) {
	tag, err := p.pool.Exec(ctx, `INSERT INTO registry (`+entryCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1) ON CONFLICT (kind, name) DO NOTHING`,
		e.Kind, e.Name, e.Status, e.Source, specOrEmpty(e.Spec), e.RequestedBy, e.ReviewedBy, e.ApprovedBy, e.Note, e.CreatedAt, e.UpdatedAt)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (p *Postgres) GetEntry(ctx context.Context, kind, name string) (Entry, error) {
	return scanEntry(p.pool.QueryRow(ctx, `SELECT `+entryCols+` FROM registry WHERE kind = $1 AND name = $2`, kind, name))
}

func (p *Postgres) ListEntries(ctx context.Context, kind string) ([]Entry, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+entryCols+` FROM registry WHERE $1 = '' OR kind = $1 ORDER BY kind, name`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateEntry(ctx context.Context, e Entry) (Entry, error) {
	row := p.pool.QueryRow(ctx, `UPDATE registry SET status=$3, source=$4, spec=$5, requested_by=$6, reviewed_by=$7,
		approved_by=$8, note=$9, updated_at=$10, version=version+1
		WHERE kind=$1 AND name=$2 AND version=$11 RETURNING `+entryCols,
		e.Kind, e.Name, e.Status, e.Source, specOrEmpty(e.Spec), e.RequestedBy, e.ReviewedBy, e.ApprovedBy, e.Note, e.UpdatedAt, e.Version)
	out, err := scanEntry(row)
	if errors.Is(err, ErrNotFound) {
		if _, gerr := p.GetEntry(ctx, e.Kind, e.Name); gerr == nil {
			return Entry{}, ErrConflict
		}
	}
	return out, err
}

// ── keys ────────────────────────────────────────────────────────────────────

const keyCols = `id, prefix, hash, name, app, team, created_by, created_at, revoked_at`

func scanKey(row pgx.Row) (Key, error) {
	var k Key
	err := row.Scan(&k.ID, &k.Prefix, &k.Hash, &k.Name, &k.App, &k.Team, &k.CreatedBy, &k.CreatedAt, &k.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	k.CreatedAt = k.CreatedAt.UTC()
	if k.RevokedAt != nil {
		t := k.RevokedAt.UTC()
		k.RevokedAt = &t
	}
	return k, err
}

func (p *Postgres) CreateKey(ctx context.Context, k Key) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO api_keys (`+keyCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		k.ID, k.Prefix, k.Hash, k.Name, k.App, k.Team, k.CreatedBy, k.CreatedAt, k.RevokedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return err
}

func (p *Postgres) KeyByHash(ctx context.Context, hash string) (Key, error) {
	return scanKey(p.pool.QueryRow(ctx, `SELECT `+keyCols+` FROM api_keys WHERE hash = $1`, hash))
}

func (p *Postgres) ListKeys(ctx context.Context) ([]Key, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+keyCols+` FROM api_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (p *Postgres) RevokeKey(ctx context.Context, id string, at time.Time) (Key, error) {
	return scanKey(p.pool.QueryRow(ctx, `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1 RETURNING `+keyCols, id, at.UTC()))
}

// ── spend ───────────────────────────────────────────────────────────────────

func (p *Postgres) AddSpend(ctx context.Context, keys []SpendKey, usd float64, tokens int64) error {
	if len(keys) == 0 {
		return nil
	}
	var sb strings.Builder
	args := []any{usd, tokens}
	sb.WriteString(`INSERT INTO spend (scope, subject, period, window_start, usd, tokens, requests) VALUES `)
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(", ")
		}
		n := len(args)
		fmt.Fprintf(&sb, "($%d, $%d, $%d, $%d, $1, $2, 1)", n+1, n+2, n+3, n+4)
		args = append(args, k.Scope, k.Subject, k.Period, k.WindowStart.UTC())
	}
	sb.WriteString(` ON CONFLICT (scope, subject, period, window_start) DO UPDATE SET
		usd = spend.usd + EXCLUDED.usd, tokens = spend.tokens + EXCLUDED.tokens, requests = spend.requests + 1`)
	_, err := p.pool.Exec(ctx, sb.String(), args...)
	return err
}

func (p *Postgres) GetSpend(ctx context.Context, k SpendKey) (Spend, error) {
	s := Spend{SpendKey: k}
	s.WindowStart = k.WindowStart.UTC()
	err := p.pool.QueryRow(ctx, `SELECT usd::float8, tokens, requests FROM spend
		WHERE scope=$1 AND subject=$2 AND period=$3 AND window_start=$4`,
		k.Scope, k.Subject, k.Period, k.WindowStart.UTC()).Scan(&s.USD, &s.Tokens, &s.Requests)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil
	}
	return s, err
}

func (p *Postgres) ListSpend(ctx context.Context, scope, period string, since time.Time) ([]Spend, error) {
	rows, err := p.pool.Query(ctx, `SELECT scope, subject, period, window_start, usd::float8, tokens, requests FROM spend
		WHERE ($1 = '' OR scope = $1) AND ($2 = '' OR period = $2) AND window_start >= $3
		ORDER BY window_start, scope, subject, period`, scope, period, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Spend
	for rows.Next() {
		var s Spend
		if err := rows.Scan(&s.Scope, &s.Subject, &s.Period, &s.WindowStart, &s.USD, &s.Tokens, &s.Requests); err != nil {
			return nil, err
		}
		s.WindowStart = s.WindowStart.UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}

// ── audit ───────────────────────────────────────────────────────────────────

func (p *Postgres) AppendAudit(ctx context.Context, seal func(audit.Head) audit.Record) (audit.Record, error) {
	var out audit.Record
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Serialise writers so the chain cannot fork.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockAudit); err != nil {
			return err
		}
		h := audit.Head{Hash: audit.GenesisHash}
		err := tx.QueryRow(ctx, `SELECT seq, hash, ts FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&h.Seq, &h.Hash, &h.Time)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		out = seal(h)
		body, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_log (seq, ts, kind, subject, decision, body, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, out.Seq, out.Time, out.Kind, out.Subject, out.Decision, string(body), out.PrevHash, out.Hash)
		return err
	})
	return out, err
}

func (p *Postgres) ListAudit(ctx context.Context, q audit.Query) ([]audit.Record, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	add("seq > $%d", q.AfterSeq)
	if q.BeforeSeq != 0 {
		add("seq < $%d", q.BeforeSeq)
	}
	if !q.From.IsZero() {
		add("ts >= $%d", q.From.UTC())
	}
	if !q.To.IsZero() {
		add("ts < $%d", q.To.UTC())
	}
	if q.Kind != "" {
		add("kind = $%d", q.Kind)
	}
	if q.Decision != "" {
		add("decision = $%d", q.Decision)
	}
	if q.Subject != "" {
		like := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q.Subject) + "/%"
		args = append(args, q.Subject, like)
		where = append(where, fmt.Sprintf("(subject = $%d OR subject LIKE $%d)", len(args)-1, len(args)))
	}
	sql := `SELECT body FROM audit_log WHERE ` + strings.Join(where, " AND ")
	if q.Desc {
		sql += " ORDER BY seq DESC"
	} else {
		sql += " ORDER BY seq"
	}
	if q.Limit > 0 {
		sql += fmt.Sprintf(" LIMIT %d", q.Limit)
	}
	rows, err := p.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Record
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) AuditHead(ctx context.Context) (int64, string, error) {
	var seq int64
	hash := audit.GenesisHash
	err := p.pool.QueryRow(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, audit.GenesisHash, nil
	}
	return seq, hash, err
}

// Exec runs raw SQL. Tests use it to prove the append-only trigger works.
func (p *Postgres) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := p.pool.Exec(ctx, sql, args...)
	return err
}
