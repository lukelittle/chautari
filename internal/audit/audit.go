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

// Package audit is Chautari's append-only, hash-chained evidence log.
//
// Each record's hash covers the previous record's hash and the record's own
// canonical JSON, so removing, reordering or editing any record breaks every
// hash after it. Verification needs nothing but an export file.
package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Kinds of audit records.
const (
	KindRequest  = "request"  // a model invocation through the checkpoint
	KindTool     = "tool"     // an MCP tool call or authorization check
	KindAgent    = "agent"    // an A2A call
	KindDecision = "decision" // a standalone policy decision
	KindApproval = "approval" // a registry lifecycle transition
	KindKey      = "key"      // API key issued or revoked
	KindConfig   = "config"   // estate loaded, gateway config rendered
	KindSession  = "session"  // admin sign-in
)

// Decisions.
const (
	Allow  = "allow"
	Deny   = "deny"
	Block  = "block"
	Redact = "redact"
	Flag   = "flag"
	Error  = "error"
	Limit  = "limit" // refused by a budget or rate limit, not by policy
	NA     = "n/a"
)

// GenesisHash is the prev_hash of the first record.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one audit entry. Field order is the canonical JSON order.
type Record struct {
	Seq      int64          `json:"seq"`
	Time     time.Time      `json:"ts"`
	Kind     string         `json:"kind"`
	Actor    string         `json:"actor"`
	Subject  string         `json:"subject"`
	Action   string         `json:"action"`
	Resource string         `json:"resource"`
	Decision string         `json:"decision"`
	Reasons  []string       `json:"reasons"`
	Details  map[string]any `json:"details"`
	PrevHash string         `json:"prev_hash"`
	Hash     string         `json:"hash"`
}

// Canonical returns the bytes the hash is computed over: the record's JSON
// with an empty hash field. Times are normalised to UTC microseconds so the
// value survives a round trip through Postgres unchanged.
func (r Record) Canonical() []byte {
	r.Hash = ""
	r.Time = Normalize(r.Time)
	if r.Reasons == nil {
		r.Reasons = []string{}
	}
	if r.Details == nil {
		r.Details = map[string]any{}
	}
	b, err := json.Marshal(r)
	if err != nil {
		// Details come from our own code; an unmarshalable value is a bug.
		panic(fmt.Sprintf("audit: canonical json: %v", err))
	}
	return b
}

// Normalize truncates a time to the precision every store preserves.
func Normalize(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// ComputeHash returns SHA-256(prev_hash || canonical JSON).
func (r Record) ComputeHash() string {
	h := sha256.New()
	h.Write([]byte(r.PrevHash))
	h.Write(r.Canonical())
	return hex.EncodeToString(h.Sum(nil))
}

// Seal fills in the chain fields of r given its predecessor.
func Seal(r Record, seq int64, prevHash string) Record {
	r.Seq = seq
	r.PrevHash = prevHash
	r.Time = Normalize(r.Time)
	if r.Reasons == nil {
		r.Reasons = []string{}
	}
	if r.Details == nil {
		r.Details = map[string]any{}
	}
	// Round-trip details through JSON so the in-memory record is exactly what
	// a reader will decode (e.g. ints become float64), keeping hashes stable.
	if b, err := json.Marshal(r.Details); err == nil {
		var d map[string]any
		if json.Unmarshal(b, &d) == nil {
			r.Details = d
		}
	}
	r.Hash = r.ComputeHash()
	return r
}

// Head describes the last record in the log.
type Head struct {
	Seq  int64
	Hash string
	Time time.Time
}

// Appender is the storage the log writes through. Append must run seal with
// the current head atomically with the insert, so concurrent writers cannot
// fork the chain.
type Appender interface {
	AppendAudit(ctx context.Context, seal func(head Head) Record) (Record, error)
}

// Log writes records.
type Log struct {
	store Appender
	now   func() time.Time
}

// NewLog returns a log backed by store.
func NewLog(store Appender) *Log { return &Log{store: store, now: time.Now} }

// WithClock overrides the clock, for tests.
func (l *Log) WithClock(now func() time.Time) *Log { l.now = now; return l }

// Write appends a record, assigning time, sequence and hashes. The time is
// taken while the append lock is held and never runs backwards, even across
// replicas with skewed clocks, so a time range of the log is always a
// contiguous, verifiable run of sequence numbers.
func (l *Log) Write(ctx context.Context, r Record) (Record, error) {
	return l.store.AppendAudit(ctx, func(h Head) Record {
		if h.Hash == "" {
			h.Hash = GenesisHash
		}
		if r.Time.IsZero() {
			r.Time = l.now()
		}
		if last := Normalize(h.Time); Normalize(r.Time).Before(last) {
			r.Time = last
		}
		return Seal(r, h.Seq+1, h.Hash)
	})
}

// VerifyResult summarises a chain check.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Records  int64  `json:"records"`
	FirstSeq int64  `json:"first_seq"`
	LastSeq  int64  `json:"last_seq"`
	HeadHash string `json:"head_hash"`
	// BrokenAt is the first sequence number whose hash or link is wrong.
	BrokenAt int64  `json:"broken_at,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

// Verifier checks records in sequence order, one at a time, so arbitrarily
// large exports verify in constant memory.
type Verifier struct {
	res  VerifyResult
	prev *Record
}

// Add checks the next record. It returns false once the chain is broken.
func (v *Verifier) Add(r Record) bool {
	if v.res.BrokenAt != 0 {
		return false
	}
	fail := func(problem string) bool {
		v.res.BrokenAt, v.res.Problem = r.Seq, problem
		return false
	}
	if v.prev == nil {
		v.res.FirstSeq = r.Seq
		if r.Seq == 1 && r.PrevHash != GenesisHash {
			return fail("first record does not link to genesis")
		}
	} else {
		if r.Seq != v.prev.Seq+1 {
			return fail(fmt.Sprintf("sequence gap: %d follows %d", r.Seq, v.prev.Seq))
		}
		if r.PrevHash != v.prev.Hash {
			return fail("prev_hash does not match the previous record's hash")
		}
	}
	if got := r.ComputeHash(); got != r.Hash {
		return fail("record hash does not match its contents")
	}
	v.res.Records++
	v.res.LastSeq = r.Seq
	v.res.HeadHash = r.Hash
	rc := r
	v.prev = &rc
	return true
}

// Result returns the outcome so far.
func (v *Verifier) Result() VerifyResult {
	r := v.res
	r.OK = r.BrokenAt == 0
	return r
}

// Verify checks a slice of records.
func Verify(records []Record) VerifyResult {
	var v Verifier
	for _, r := range records {
		if !v.Add(r) {
			break
		}
	}
	return v.Result()
}

// VerifyJSONL checks an export produced by WriteJSONL.
func VerifyJSONL(r io.Reader) (VerifyResult, error) {
	var v Verifier
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return v.Result(), fmt.Errorf("line %d: %w", line, err)
		}
		if !v.Add(rec) {
			break
		}
	}
	return v.Result(), sc.Err()
}

// WriteJSONL writes records one JSON object per line. This is the format
// auditors receive; `chautari audit verify` re-checks it offline.
func WriteJSONL(w io.Writer, records []Record) error {
	enc := json.NewEncoder(w)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// CSVHeader is the column order of WriteCSV.
var CSVHeader = []string{"seq", "ts", "kind", "actor", "subject", "action", "resource", "decision", "reasons", "details", "prev_hash", "hash"}

// WriteCSV writes records as CSV for spreadsheet-minded reviewers. Details
// are embedded as JSON; reasons are joined with "; ".
func WriteCSV(w io.Writer, records []Record, header bool) error {
	cw := csv.NewWriter(w)
	if header {
		if err := cw.Write(CSVHeader); err != nil {
			return err
		}
	}
	for _, r := range records {
		d, _ := json.Marshal(r.Details)
		row := []string{
			strconv.FormatInt(r.Seq, 10), r.Time.UTC().Format(time.RFC3339Nano), r.Kind, r.Actor, r.Subject,
			r.Action, r.Resource, r.Decision, strings.Join(r.Reasons, "; "), string(d), r.PrevHash, r.Hash,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// Query filters records for listing and export.
type Query struct {
	From, To  time.Time // inclusive, exclusive; zero means unbounded
	Kind      string
	Subject   string
	Decision  string
	AfterSeq  int64 // return records with seq > AfterSeq
	BeforeSeq int64 // if non-zero, return records with seq < BeforeSeq
	Limit     int   // 0 means no limit
	Desc      bool  // newest first
}

// Match reports whether r satisfies q's filters (not paging).
func (q Query) Match(r Record) bool {
	if !q.From.IsZero() && r.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !r.Time.Before(q.To) {
		return false
	}
	if q.Kind != "" && r.Kind != q.Kind {
		return false
	}
	if q.Subject != "" && r.Subject != q.Subject && !strings.HasPrefix(r.Subject, q.Subject+"/") {
		return false
	}
	if q.Decision != "" && r.Decision != q.Decision {
		return false
	}
	if q.BeforeSeq != 0 && r.Seq >= q.BeforeSeq {
		return false
	}
	return r.Seq > q.AfterSeq
}
