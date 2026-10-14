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

package audit_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/store"
)

func seed(t *testing.T, n int) (*store.Memory, []audit.Record) {
	t.Helper()
	s := store.NewMemory()
	clock := time.Date(2026, 10, 13, 9, 0, 0, 123456789, time.UTC)
	log := audit.NewLog(s).WithClock(func() time.Time { clock = clock.Add(time.Second); return clock })
	for i := 0; i < n; i++ {
		_, err := log.Write(context.Background(), audit.Record{
			Kind: audit.KindRequest, Actor: "key_x", Subject: "lending/loan-assistant", Action: "model.invoke",
			Resource: "model/claude-sonnet", Decision: audit.Allow, Reasons: []string{"entitled"},
			Details: map[string]any{"prompt_tokens": 120 + i, "cost_usd": 0.00042, "findings": []string{"email"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := s.ListAudit(context.Background(), audit.Query{})
	return s, recs
}

func TestChainVerifies(t *testing.T) {
	_, recs := seed(t, 10)
	res := audit.Verify(recs)
	if !res.OK || res.Records != 10 || res.FirstSeq != 1 || res.LastSeq != 10 || res.HeadHash != recs[9].Hash {
		t.Fatalf("%+v", res)
	}
	if recs[0].PrevHash != audit.GenesisHash {
		t.Fatal("first record must link to genesis")
	}
	if recs[0].Time.Nanosecond()%1000 != 0 {
		t.Fatal("times must be normalised to microseconds")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func(*store.Memory){
		"edit a decision":   func(s *store.Memory) { s.Tamper(4, func(r *audit.Record) { r.Decision = audit.Deny }) },
		"edit details":      func(s *store.Memory) { s.Tamper(4, func(r *audit.Record) { r.Details["cost_usd"] = 0.0 }) },
		"backdate a record": func(s *store.Memory) { s.Tamper(4, func(r *audit.Record) { r.Time = r.Time.Add(-time.Hour) }) },
		"re-hash one record": func(s *store.Memory) {
			s.Tamper(4, func(r *audit.Record) { r.Actor = "someone-else"; r.Hash = r.ComputeHash() })
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := seed(t, 8)
			tamper(s)
			recs, _ := s.ListAudit(context.Background(), audit.Query{})
			res := audit.Verify(recs)
			if res.OK {
				t.Fatal("tampering went undetected")
			}
			if res.BrokenAt != 4 && res.BrokenAt != 5 {
				t.Fatalf("broken at %d, want 4 or 5: %s", res.BrokenAt, res.Problem)
			}
		})
	}
	t.Run("delete a record", func(t *testing.T) {
		_, recs := seed(t, 8)
		recs = append(recs[:3], recs[4:]...)
		if res := audit.Verify(recs); res.OK || res.BrokenAt != 5 || !strings.Contains(res.Problem, "gap") {
			t.Fatalf("%+v", res)
		}
	})
}

func TestJSONLExportRoundTrip(t *testing.T) {
	_, recs := seed(t, 25)
	var buf bytes.Buffer
	if err := audit.WriteJSONL(&buf, recs); err != nil {
		t.Fatal(err)
	}
	res, err := audit.VerifyJSONL(&buf)
	if err != nil || !res.OK || res.Records != 25 {
		t.Fatalf("%+v %v", res, err)
	}
	// Flip one byte of the export: verification must fail.
	var buf2 bytes.Buffer
	audit.WriteJSONL(&buf2, recs)
	tampered := strings.Replace(buf2.String(), `"prompt_tokens":130`, `"prompt_tokens":13`, 1)
	res, err = audit.VerifyJSONL(strings.NewReader(tampered))
	if err != nil || res.OK {
		t.Fatalf("tampered export verified: %+v %v", res, err)
	}
}

func TestPartialExportVerifiesInternally(t *testing.T) {
	_, recs := seed(t, 10)
	if res := audit.Verify(recs[4:]); !res.OK || res.FirstSeq != 5 {
		t.Fatalf("contiguous slice should verify: %+v", res)
	}
}

func TestCSV(t *testing.T) {
	_, recs := seed(t, 3)
	var buf bytes.Buffer
	if err := audit.WriteCSV(&buf, recs, true); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 4 || rows[0][0] != "seq" || rows[1][7] != "allow" || rows[3][11] != recs[2].Hash {
		t.Fatalf("%v %v", rows, err)
	}
}

func TestQueryMatch(t *testing.T) {
	r := audit.Record{Seq: 5, Time: time.Unix(100, 0), Kind: "request", Subject: "lending/app", Decision: "deny"}
	if !(audit.Query{Subject: "lending"}).Match(r) || (audit.Query{Subject: "lend"}).Match(r) {
		t.Fatal("subject prefix must match on team boundary")
	}
	if (audit.Query{AfterSeq: 5}).Match(r) || !(audit.Query{From: time.Unix(100, 0), To: time.Unix(101, 0)}).Match(r) {
		t.Fatal("seq/time bounds")
	}
}
