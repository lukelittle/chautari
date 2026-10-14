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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
)

// Contract runs the same behavioural tests against every Store.
func contract(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

	t.Run("registry", func(t *testing.T) {
		s := newStore(t)
		e := Entry{Kind: "model", Name: "m", Status: "requested", Source: "api", Spec: []byte(`{"name":"m"}`), RequestedBy: "alice", CreatedAt: now, UpdatedAt: now}
		created, err := s.PutEntryIfAbsent(ctx, e)
		if err != nil || !created {
			t.Fatalf("put: %v %v", created, err)
		}
		if created, _ := s.PutEntryIfAbsent(ctx, e); created {
			t.Fatal("second put must not overwrite")
		}
		got, err := s.GetEntry(ctx, "model", "m")
		if err != nil || got.Version != 1 || got.RequestedBy != "alice" || !strings.Contains(string(got.Spec), `"m"`) {
			t.Fatalf("get: %+v %v", got, err)
		}
		got.Status, got.ReviewedBy = "reviewed", "bob"
		upd, err := s.UpdateEntry(ctx, got)
		if err != nil || upd.Version != 2 || upd.Status != "reviewed" {
			t.Fatalf("update: %+v %v", upd, err)
		}
		if _, err := s.UpdateEntry(ctx, got); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale update: want ErrConflict, got %v", err)
		}
		if _, err := s.GetEntry(ctx, "model", "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		s.PutEntryIfAbsent(ctx, Entry{Kind: "tool", Name: "t", Status: "approved", Source: "cdl", CreatedAt: now, UpdatedAt: now})
		all, _ := s.ListEntries(ctx, "")
		models, _ := s.ListEntries(ctx, "model")
		if len(all) != 2 || len(models) != 1 {
			t.Fatalf("list: %d %d", len(all), len(models))
		}
	})

	t.Run("keys", func(t *testing.T) {
		s := newStore(t)
		k := Key{ID: "key_1", Prefix: "ck_abc", Hash: "h1", Name: "prod", App: "a", Team: "t", CreatedBy: "admin", CreatedAt: now}
		if err := s.CreateKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateKey(ctx, Key{ID: "key_2", Hash: "h1", CreatedAt: now}); !errors.Is(err, ErrConflict) {
			t.Fatalf("duplicate hash: %v", err)
		}
		got, err := s.KeyByHash(ctx, "h1")
		if err != nil || got.ID != "key_1" || !got.Active() {
			t.Fatalf("by hash: %+v %v", got, err)
		}
		r, err := s.RevokeKey(ctx, "key_1", now.Add(time.Hour))
		if err != nil || r.Active() {
			t.Fatalf("revoke: %+v %v", r, err)
		}
		again, _ := s.RevokeKey(ctx, "key_1", now.Add(2*time.Hour))
		if !again.RevokedAt.Equal(*r.RevokedAt) {
			t.Fatal("revoking twice must keep the first timestamp")
		}
		if _, err := s.KeyByHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		list, _ := s.ListKeys(ctx)
		if len(list) != 1 {
			t.Fatalf("list = %d", len(list))
		}
	})

	t.Run("spend", func(t *testing.T) {
		s := newStore(t)
		keys := []SpendKey{
			{Scope: "team", Subject: "lending", Period: "month", WindowStart: now},
			{Scope: "app", Subject: "loan", Period: "month", WindowStart: now},
		}
		for i := 0; i < 3; i++ {
			if err := s.AddSpend(ctx, keys, 0.125, 100); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.GetSpend(ctx, keys[0])
		if err != nil || got.USD != 0.375 || got.Tokens != 300 || got.Requests != 3 {
			t.Fatalf("spend = %+v %v", got, err)
		}
		empty, err := s.GetSpend(ctx, SpendKey{Scope: "team", Subject: "x", Period: "day", WindowStart: now})
		if err != nil || empty.USD != 0 {
			t.Fatalf("empty = %+v %v", empty, err)
		}
		list, _ := s.ListSpend(ctx, "team", "month", now.Add(-time.Hour))
		if len(list) != 1 || list[0].Subject != "lending" {
			t.Fatalf("list = %+v", list)
		}
	})

	t.Run("audit chain", func(t *testing.T) {
		s := newStore(t)
		log := audit.NewLog(s).WithClock(func() time.Time { return now })
		for i := 0; i < 5; i++ {
			_, err := log.Write(ctx, audit.Record{Kind: audit.KindRequest, Actor: "key_1", Subject: "lending/loan", Action: "model.invoke",
				Resource: "model/claude", Decision: audit.Allow, Details: map[string]any{"tokens": i * 10, "cost_usd": 0.0001 * float64(i)}})
			if err != nil {
				t.Fatal(err)
			}
		}
		recs, err := s.ListAudit(ctx, audit.Query{})
		if err != nil || len(recs) != 5 {
			t.Fatalf("list: %d %v", len(recs), err)
		}
		if res := audit.Verify(recs); !res.OK || res.Records != 5 || res.LastSeq != 5 {
			t.Fatalf("verify: %+v", res)
		}
		seq, hash, _ := s.AuditHead(ctx)
		if seq != 5 || hash != recs[4].Hash {
			t.Fatalf("head = %d %s", seq, hash)
		}
		desc, _ := s.ListAudit(ctx, audit.Query{Desc: true, Limit: 2})
		if len(desc) != 2 || desc[0].Seq != 5 {
			t.Fatalf("desc = %+v", desc)
		}
		bySubject, _ := s.ListAudit(ctx, audit.Query{Subject: "lending"})
		if len(bySubject) != 5 {
			t.Fatalf("subject filter = %d", len(bySubject))
		}
	})

	t.Run("audit times never run backwards", func(t *testing.T) {
		s := newStore(t)
		// A clock that jumps backwards, as skewed replicas would.
		times := []time.Time{now, now.Add(-time.Hour), now.Add(time.Second)}
		i := 0
		log := audit.NewLog(s).WithClock(func() time.Time { t := times[i%3]; i++; return t })
		for j := 0; j < 3; j++ {
			log.Write(ctx, audit.Record{Kind: audit.KindDecision, Decision: audit.Deny})
		}
		recs, _ := s.ListAudit(ctx, audit.Query{})
		for j := 1; j < len(recs); j++ {
			if recs[j].Time.Before(recs[j-1].Time) {
				t.Fatalf("seq %d is earlier than seq %d", recs[j].Seq, recs[j-1].Seq)
			}
		}
		// So any time range is a contiguous run that verifies.
		part, _ := s.ListAudit(ctx, audit.Query{From: now})
		if res := audit.Verify(part); !res.OK {
			t.Fatalf("time-range export: %+v", res)
		}
	})

	t.Run("audit subject filter treats wildcards literally", func(t *testing.T) {
		s := newStore(t)
		log := audit.NewLog(s)
		log.Write(ctx, audit.Record{Kind: audit.KindRequest, Subject: "lending/app", Decision: audit.Allow})
		log.Write(ctx, audit.Record{Kind: audit.KindRequest, Subject: "x_ending/app", Decision: audit.Allow})
		for _, q := range []string{"%", "_ending", "lend%"} {
			if recs, _ := s.ListAudit(ctx, audit.Query{Subject: q}); len(recs) != 0 {
				t.Errorf("subject %q matched %d records", q, len(recs))
			}
		}
		if recs, _ := s.ListAudit(ctx, audit.Query{Subject: "x_ending"}); len(recs) != 1 {
			t.Errorf("exact team prefix must still match")
		}
	})

	t.Run("audit concurrent writers keep one chain", func(t *testing.T) {
		s := newStore(t)
		log := audit.NewLog(s)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := log.Write(ctx, audit.Record{Kind: audit.KindDecision, Actor: fmt.Sprint(i), Decision: audit.Deny}); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		recs, _ := s.ListAudit(ctx, audit.Query{})
		if res := audit.Verify(recs); !res.OK || res.Records != 20 {
			t.Fatalf("verify: %+v", res)
		}
	})
}

func TestMemoryStore(t *testing.T) {
	contract(t, func(t *testing.T) Store { return NewMemory() })
}

// TestPostgresStore runs when CHAUTARI_TEST_DATABASE_URL points at a
// throwaway database (CI provides one; `make test-pg` starts one locally).
func TestPostgresStore(t *testing.T) {
	url := os.Getenv("CHAUTARI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CHAUTARI_TEST_DATABASE_URL not set")
	}
	open := func(t *testing.T) Store {
		ctx := context.Background()
		p, err := OpenPostgres(ctx, url, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		// Fresh schema per subtest. Dropping the table is the only way past
		// the append-only triggers, which is the point.
		for _, sql := range []string{`DROP TABLE IF EXISTS audit_log, registry, api_keys, spend, schema_migrations CASCADE`} {
			if err := p.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
		}
		p.Close()
		p, err = OpenPostgres(ctx, url, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	contract(t, open)

	t.Run("audit log is append-only in the database", func(t *testing.T) {
		p := open(t).(*Postgres)
		ctx := context.Background()
		if _, err := audit.NewLog(p).Write(ctx, audit.Record{Kind: audit.KindConfig, Decision: audit.NA}); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			`UPDATE audit_log SET decision = 'allow'`,
			`DELETE FROM audit_log`,
			`TRUNCATE audit_log`,
		} {
			err := p.Exec(ctx, sql)
			if err == nil || !strings.Contains(err.Error(), "append-only") {
				t.Errorf("%s: want append-only error, got %v", sql, err)
			}
		}
	})

	t.Run("migrations are idempotent", func(t *testing.T) {
		open(t)
		p, err := OpenPostgres(context.Background(), url, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		p.Close()
	})
}
