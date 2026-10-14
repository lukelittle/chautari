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

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/budget"
	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/controls"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/policy"
	"github.com/lukelittle/chautari/internal/registry"
	"github.com/lukelittle/chautari/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v) //nolint:errcheck
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// csrfSafe reports whether a cookie-authenticated request may change state.
// Browsers cannot attach a custom header to a cross-site request without a
// CORS preflight, which Chautari never grants, so its presence proves the
// request came from the admin UI's own scripts.
func csrfSafe(r *http.Request, id adminIdentity) bool {
	if !id.Session {
		return true // bearer tokens are not sent ambiently by browsers
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return r.Header.Get("X-Chautari-Actor") != "" || r.Header.Get("X-Requested-With") != ""
}

// admin wraps an admin handler with authentication.
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.adminAuth(r)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		if !csrfSafe(r, id) {
			jsonError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		h(w, r)
	}
}

// mutating additionally requires a named actor, because approvals and keys
// must be attributable to a person.
func (s *Server) mutating(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.adminAuth(r)
		if !ok {
			jsonError(w, http.StatusUnauthorized, "admin token required")
			return
		}
		if !csrfSafe(r, id) {
			jsonError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		if id.Actor == "" {
			jsonError(w, http.StatusBadRequest, "set X-Chautari-Actor to the person taking this action")
			return
		}
		h(w, r, id.Actor)
	}
}

// ActorsVerified reports whether admin identities come from credentials
// (per-person tokens) rather than from what people type.
func (s *Server) ActorsVerified() bool {
	return len(s.cfg.AdminTokens) > 0 && s.cfg.AdminToken == ""
}

func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/session", s.login)
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("DELETE /api/session", s.logout)

	mux.HandleFunc("GET /api/overview", s.admin(s.overview))
	mux.HandleFunc("GET /api/estate", s.admin(s.getEstate))
	mux.HandleFunc("GET /api/registry", s.admin(s.listRegistry))
	mux.HandleFunc("POST /api/registry", s.mutating(s.requestEntry))
	mux.HandleFunc("POST /api/registry/{kind}/{name}/{action}", s.mutating(s.transition))
	mux.HandleFunc("GET /api/keys", s.admin(s.listKeys))
	mux.HandleFunc("POST /api/keys", s.mutating(s.createKey))
	mux.HandleFunc("DELETE /api/keys/{id}", s.mutating(s.revokeKey))
	mux.HandleFunc("GET /api/budgets", s.admin(s.budgets))
	mux.HandleFunc("GET /api/spend", s.admin(s.spend))
	mux.HandleFunc("GET /api/audit", s.admin(s.listAudit))
	mux.HandleFunc("GET /api/audit/export", s.admin(s.exportAudit))
	mux.HandleFunc("GET /api/audit/verify", s.admin(s.verifyAudit))
	mux.HandleFunc("GET /api/reports/controls", s.admin(s.controlsReport))
	mux.HandleFunc("POST /api/policy/decide", s.admin(s.decide))
	mux.HandleFunc("GET /api/policy/matrix", s.admin(s.matrix))
	mux.HandleFunc("POST /api/guardrails/test", s.admin(s.testGuardrails))
	mux.HandleFunc("GET /api/gateway/config", s.admin(s.gatewayConfig))
}

// ── session (browser) ──────────────────────────────────────────────────────

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.logins.blocked(ip, s.now()) {
		jsonError(w, http.StatusTooManyRequests, "too many failed sign-ins; wait a few minutes")
		return
	}
	var req struct {
		Token string `json:"token"`
		Actor string `json:"actor"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "body must be {\"token\": \"...\", \"actor\": \"you@example.com\"}")
		return
	}
	id, ok := s.matchToken(req.Token)
	if !ok {
		s.logins.fail(ip, s.now())
		s.writeAudit(r.Context(), audit.Record{Kind: audit.KindSession, Actor: "unknown", Action: "session.login", //nolint:errcheck
			Resource: "admin", Decision: audit.Deny, Reasons: []string{"wrong admin token"}, Details: map[string]any{"ip": ip}})
		jsonError(w, http.StatusUnauthorized, "wrong admin token")
		return
	}
	if !id.Verified {
		id.Actor = strings.TrimSpace(req.Actor)
		if id.Actor == "" {
			jsonError(w, http.StatusBadRequest, "tell us who you are: approvals are attributed to a person")
			return
		}
	}
	if err := s.writeAudit(r.Context(), audit.Record{Kind: audit.KindSession, Actor: id.Actor, Action: "session.login",
		Resource: "admin", Decision: audit.Allow, Details: map[string]any{"ip": ip, "verified": id.Verified}}); err != nil {
		jsonError(w, http.StatusServiceUnavailable, "the audit log is unavailable")
		return
	}
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.newSession(id), Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionLifetime.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"actor": id.Actor, "verified": id.Verified})
}

// session tells the UI who is signed in.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	id, ok := s.adminAuth(r)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "not signed in")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actor": id.Actor, "verified": id.Verified, "per_person_tokens": s.ActorsVerified()})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// matrix answers, for every team and model, whether a request at the given
// data class (default: the estate's) would be allowed, and why not.
func (s *Server) matrix(w http.ResponseWriter, r *http.Request) {
	dc := r.URL.Query().Get("data_class")
	if dc == "" {
		dc = string(s.runtime().estate.DefaultDataClass)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data_class": dc, "teams": s.AccessMatrix(r.Context(), dc)})
}

// ── overview ───────────────────────────────────────────────────────────────

// Overview is the admin home page's data.
type Overview struct {
	Estate  EstateSummary             `json:"estate"`
	Counts  map[string]map[string]int `json:"registry"`
	Pending []store.Entry             `json:"pending"`
	Budgets []budget.Status           `json:"budgets"`
	Recent  RecentActivity            `json:"recent"`
	Chain   audit.VerifyResult        `json:"chain"`
	Keys    KeyCounts                 `json:"keys"`
	Daily   []DailySpend              `json:"daily_spend"`
}

// EstateSummary identifies the running estate.
type EstateSummary struct {
	Name        string    `json:"name"`
	Org         string    `json:"org"`
	Environment string    `json:"environment"`
	Dataplane   string    `json:"dataplane"`
	CDLFile     string    `json:"cdl_file"`
	CDLSHA256   string    `json:"cdl_sha256"`
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
	Teams       int       `json:"teams"`
	Apps        int       `json:"apps"`
	Policies    int       `json:"policies"`
}

// RecentActivity summarises the last 24 hours of request traffic.
type RecentActivity struct {
	Requests   int            `json:"requests"`
	ByDecision map[string]int `json:"by_decision"`
	Blocks     []audit.Record `json:"blocks"` // latest denials and guardrail blocks
	SpendUSD   float64        `json:"spend_usd"`
	Tokens     int64          `json:"tokens"`
}

// KeyCounts summarises API keys.
type KeyCounts struct {
	Active  int `json:"active"`
	Revoked int `json:"revoked"`
}

// DailySpend is one team's spend on one UTC day.
type DailySpend struct {
	Day  string  `json:"day"`
	Team string  `json:"team"`
	USD  float64 `json:"usd"`
}

func (s *Server) summary() EstateSummary {
	e := s.runtime().estate
	return EstateSummary{Name: e.Name, Org: e.Org, Environment: e.Environment, Dataplane: s.cfg.Adapter.Name(),
		CDLFile: e.Source.File, CDLSHA256: e.Source.SHA256, Version: s.cfg.Version, StartedAt: s.started,
		Teams: len(e.Teams), Apps: len(e.Apps), Policies: len(e.Policies)}
}

func (s *Server) registryCounts(ctx context.Context) (map[string]map[string]int, error) {
	es, err := s.registry.List(ctx, "")
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]int{"model": {}, "tool": {}, "agent": {}}
	for _, e := range es {
		out[e.Kind][e.Status]++
	}
	return out, nil
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt := s.runtime()
	ov := Overview{Estate: s.summary()}
	var err error
	if ov.Counts, err = s.registryCounts(ctx); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if ov.Pending, err = s.registry.Pending(ctx); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if ov.Pending == nil {
		ov.Pending = []store.Entry{}
	}
	if ov.Budgets, err = s.limiter.Statuses(ctx, rt.estate); err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	since := s.now().Add(-24 * time.Hour)
	recs, err := s.cfg.Store.ListAudit(ctx, audit.Query{From: since, Kind: audit.KindRequest})
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	ov.Recent.ByDecision = map[string]int{}
	ov.Recent.Blocks = []audit.Record{}
	for i := len(recs) - 1; i >= 0; i-- {
		rec := recs[i]
		ov.Recent.Requests++
		ov.Recent.ByDecision[rec.Decision]++
		if c, ok := rec.Details["cost_usd"].(float64); ok {
			ov.Recent.SpendUSD += c
		}
		if p, ok := rec.Details["prompt_tokens"].(float64); ok {
			ov.Recent.Tokens += int64(p)
		}
		if c, ok := rec.Details["completion_tokens"].(float64); ok {
			ov.Recent.Tokens += int64(c)
		}
		if (rec.Decision == audit.Deny || rec.Decision == audit.Block || rec.Decision == audit.Limit) && len(ov.Recent.Blocks) < 12 {
			ov.Recent.Blocks = append(ov.Recent.Blocks, rec)
		}
	}
	ov.Chain = s.verify(ctx, overviewVerifyWindow)
	keys, err := s.cfg.Store.ListKeys(ctx)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	for _, k := range keys {
		if k.Active() {
			ov.Keys.Active++
		} else {
			ov.Keys.Revoked++
		}
	}
	day := budget.WindowStart(estate.Day, s.now()).AddDate(0, 0, -13)
	spend, err := s.cfg.Store.ListSpend(ctx, "team", "day", day)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	ov.Daily = []DailySpend{}
	for _, sp := range spend {
		ov.Daily = append(ov.Daily, DailySpend{Day: sp.WindowStart.Format("2006-01-02"), Team: sp.Subject, USD: sp.USD})
	}
	writeJSON(w, http.StatusOK, ov)
}

// overviewVerifyWindow bounds the chain check on the overview page; the full
// check is /api/audit/verify and the controls report.
const overviewVerifyWindow = 10000

// verify checks the most recent `limit` records (0 = all).
func (s *Server) verify(ctx context.Context, limit int) audit.VerifyResult {
	q := audit.Query{}
	if limit > 0 {
		head, _, err := s.cfg.Store.AuditHead(ctx)
		if err == nil && head > int64(limit) {
			q.AfterSeq = head - int64(limit)
		}
	}
	recs, err := s.cfg.Store.ListAudit(ctx, q)
	if err != nil {
		return audit.VerifyResult{Problem: err.Error()}
	}
	return audit.Verify(recs)
}

// ── estate & registry ──────────────────────────────────────────────────────

func (s *Server) getEstate(w http.ResponseWriter, r *http.Request) {
	rt := s.runtime()
	writeJSON(w, http.StatusOK, map[string]any{"summary": s.summary(), "estate": rt.estate, "status": rt.status})
}

func (s *Server) listRegistry(w http.ResponseWriter, r *http.Request) {
	es, err := s.registry.List(r.Context(), r.URL.Query().Get("kind"))
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if es == nil {
		es = []store.Entry{}
	}
	writeJSON(w, http.StatusOK, es)
}

func (s *Server) requestEntry(w http.ResponseWriter, r *http.Request, who string) {
	var req struct {
		Kind string          `json:"kind"`
		Name string          `json:"name"`
		Spec json.RawMessage `json:"spec"`
		Note string          `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !cdl.ValidName(req.Name) {
		jsonError(w, http.StatusBadRequest, "name must be a CDL identifier: ASCII letters, digits, '_', '.', '-', starting with a letter or '_', at most 63 characters")
		return
	}
	if req.Kind == registry.KindModel {
		var m estate.Model
		if json.Unmarshal(req.Spec, &m) != nil || m.Provider == "" {
			jsonError(w, http.StatusBadRequest, `a model request needs spec.provider (and usually spec.upstream_id, spec.data_class, spec.cost_in_usd_per_mtok)`)
			return
		}
		if _, ok := s.runtime().estate.Provider(m.Provider); !ok {
			jsonError(w, http.StatusBadRequest, fmt.Sprintf("provider %q is not declared in the estate", m.Provider))
			return
		}
	}
	en, err := s.registry.Request(r.Context(), req.Kind, req.Name, who, req.Spec, req.Note)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrConflict) {
			status = http.StatusConflict
		}
		jsonError(w, status, err.Error())
		return
	}
	s.Reload(r.Context()) //nolint:errcheck
	writeJSON(w, http.StatusCreated, en)
}

func (s *Server) transition(w http.ResponseWriter, r *http.Request, who string) {
	var req struct {
		Note string `json:"note"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req) //nolint:errcheck
	en, err := s.registry.Transition(r.Context(), r.PathValue("kind"), r.PathValue("name"), r.PathValue("action"), who, req.Note)
	switch {
	case errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "no such registry entry")
		return
	case errors.Is(err, registry.ErrSeparationOfDuty):
		jsonError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, registry.ErrInvalidTransition), errors.Is(err, store.ErrConflict):
		jsonError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.Reload(r.Context()); err != nil {
		jsonError(w, http.StatusInternalServerError, "transition recorded but reload failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, en)
}

// ── keys ───────────────────────────────────────────────────────────────────

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	ks, err := s.cfg.Store.ListKeys(r.Context())
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if ks == nil {
		ks = []store.Key{}
	}
	writeJSON(w, http.StatusOK, ks)
}

// IssuedKey is returned exactly once, when a key is created.
type IssuedKey struct {
	store.Key
	Secret string `json:"secret"`
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, who string) {
	var req struct {
		App  string `json:"app"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	app, ok := s.runtime().estate.App(req.App)
	if !ok {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("app %q is not in the estate", req.App))
		return
	}
	if req.Name == "" {
		req.Name = "default"
	}
	secret := NewKeySecret()
	k := store.Key{ID: "key_" + strings.ToLower(secret[3:15]), Prefix: secret[:10], Hash: HashKey(secret), Name: req.Name,
		App: app.Name, Team: app.Team, CreatedBy: who, CreatedAt: s.now().UTC()}
	// Evidence first: no key exists that the audit log doesn't know about.
	if !s.mustAudit(w, r.Context(), audit.Record{Kind: audit.KindKey, Actor: who, Subject: app.Team + "/" + app.Name,
		Action: "key.issue", Resource: "key/" + k.ID, Decision: audit.NA, Details: map[string]any{"name": k.Name, "prefix": k.Prefix}}) {
		return
	}
	if err := s.cfg.Store.CreateKey(r.Context(), k); err != nil {
		s.writeAudit(r.Context(), audit.Record{Kind: audit.KindKey, Actor: who, Subject: app.Team + "/" + app.Name, //nolint:errcheck
			Action: "key.issue.abandoned", Resource: "key/" + k.ID, Decision: audit.Error, Reasons: []string{err.Error()}})
		s.log.Error("key issue failed", "err", err)
		jsonError(w, 500, "could not store the key")
		return
	}
	writeJSON(w, http.StatusCreated, IssuedKey{Key: k, Secret: secret})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, who string) {
	k, err := s.cfg.Store.RevokeKey(r.Context(), r.PathValue("id"), s.now())
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, http.StatusNotFound, "no such key")
		return
	} else if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	// Revocation is never held back for want of an audit record: a key that
	// should be dead stays dead. The failure is logged loudly instead.
	s.writeAudit(r.Context(), audit.Record{Kind: audit.KindKey, Actor: who, Subject: k.Team + "/" + k.App, //nolint:errcheck
		Action: "key.revoke", Resource: "key/" + k.ID, Decision: audit.NA})
	writeJSON(w, http.StatusOK, k)
}

// ── spend ──────────────────────────────────────────────────────────────────

func (s *Server) budgets(w http.ResponseWriter, r *http.Request) {
	st, err := s.limiter.Statuses(r.Context(), s.runtime().estate)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) spend(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := s.now().AddDate(0, 0, -30)
	if v := q.Get("since"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "since must be YYYY-MM-DD")
			return
		}
		since = t
	}
	period := q.Get("period")
	if period == "" {
		period = "day"
	}
	sp, err := s.cfg.Store.ListSpend(r.Context(), q.Get("scope"), period, since)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if sp == nil {
		sp = []store.Spend{}
	}
	writeJSON(w, http.StatusOK, sp)
}

// ── audit ──────────────────────────────────────────────────────────────────

func auditQuery(r *http.Request) (audit.Query, error) {
	v := r.URL.Query()
	q := audit.Query{Kind: v.Get("kind"), Subject: v.Get("subject"), Decision: v.Get("decision")}
	for name, dst := range map[string]*time.Time{"from": &q.From, "to": &q.To} {
		if s := v.Get(name); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				if t, err = time.Parse("2006-01-02", s); err != nil {
					return q, fmt.Errorf("%s must be RFC 3339 or YYYY-MM-DD", name)
				}
			}
			*dst = t
		}
	}
	if s := v.Get("after"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return q, errors.New("after must be a sequence number")
		}
		q.AfterSeq = n
	}
	return q, nil
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q, err := auditQuery(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	q.Desc = true
	q.Limit = 100
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 1000 {
		q.Limit = l
	}
	if b := r.URL.Query().Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n < 1 {
			jsonError(w, http.StatusBadRequest, "before must be a sequence number")
			return
		}
		q.BeforeSeq = n
	}
	recs, err := s.cfg.Store.ListAudit(r.Context(), q)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

// exportAudit streams a contiguous range of the log. Filtering by kind would
// leave holes in the chain, so exports only accept a time range.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	q, err := auditQuery(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if q.Kind != "" || q.Subject != "" || q.Decision != "" {
		jsonError(w, http.StatusBadRequest, "exports are contiguous so they can be verified: filter by from/to only")
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "jsonl"
	}
	stamp := s.now().UTC().Format("20060102T150405Z")
	name := fmt.Sprintf("chautari-audit-%s-%s", s.runtime().estate.Name, stamp)
	const page = 5000
	header := true
	switch format {
	case "jsonl":
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.jsonl"`)
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	default:
		jsonError(w, http.StatusBadRequest, "format must be jsonl or csv")
		return
	}
	for {
		q.Limit = page
		recs, err := s.cfg.Store.ListAudit(r.Context(), q)
		if err != nil {
			s.log.Error("audit export failed", "err", err)
			return
		}
		if format == "jsonl" {
			audit.WriteJSONL(w, recs) //nolint:errcheck
		} else {
			audit.WriteCSV(w, recs, header) //nolint:errcheck
			header = false
		}
		if len(recs) < page {
			return
		}
		q.AfterSeq = recs[len(recs)-1].Seq
	}
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.verify(r.Context(), 0))
}

// ── reports ────────────────────────────────────────────────────────────────

// Evidence gathers live facts for the controls report.
func (s *Server) Evidence(ctx context.Context) (*controls.Evidence, error) {
	ev := &controls.Evidence{GeneratedAt: s.now().UTC(), ActorsVerified: s.ActorsVerified(), AuditByKind: map[string]int{}, AuditByDecision: map[string]int{}, SpendByTeam: map[string]float64{}}
	var err error
	if ev.RegistryCounts, err = s.registryCounts(ctx); err != nil {
		return nil, err
	}
	recs, err := s.cfg.Store.ListAudit(ctx, audit.Query{})
	if err != nil {
		return nil, err
	}
	res := audit.Verify(recs)
	ev.ChainOK, ev.ChainHead, ev.ChainChecked, ev.AuditRecords = res.OK, res.HeadHash, res.Records, int64(len(recs))
	for i := len(recs) - 1; i >= 0; i-- {
		rec := recs[i]
		ev.AuditByKind[rec.Kind]++
		if rec.Kind == audit.KindRequest || rec.Kind == audit.KindTool || rec.Kind == audit.KindAgent {
			ev.AuditByDecision[rec.Decision]++
		}
		if rec.Kind == audit.KindApproval && strings.HasPrefix(rec.Action, "registry.") && rec.Action != "registry.seed" && len(ev.Approvals) < 10 {
			ev.Approvals = append(ev.Approvals, fmt.Sprintf("%s %s %s → %s", rec.Time.UTC().Format("2006-01-02 15:04"), rec.Actor, rec.Resource, rec.Decision))
		}
	}
	keys, err := s.cfg.Store.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k.Active() {
			ev.ActiveKeys++
		} else {
			ev.RevokedKeys++
		}
	}
	st, err := s.limiter.Statuses(ctx, s.runtime().estate)
	if err != nil {
		return nil, err
	}
	for _, b := range st {
		if b.Scope == "team" && b.Period == "month" {
			ev.SpendByTeam[b.Name] = b.UsedUSD
		}
	}
	return ev, nil
}

func (s *Server) controlsReport(w http.ResponseWriter, r *http.Request) {
	ev, err := s.Evidence(r.Context())
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	rep := controls.Build(s.runtime().estate, ev)
	switch r.URL.Query().Get("format") {
	case "md", "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write(controls.Markdown(rep))
	case "html":
		b, err := controls.HTML(rep)
		if err != nil {
			jsonError(w, 500, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	default:
		writeJSON(w, http.StatusOK, rep)
	}
}

// ── tools for the policy and guardrail pages ───────────────────────────────

// decide is a dry run: it evaluates policy without auditing, so the UI can
// draw an access matrix.
func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var in policy.Input
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	writeJSON(w, http.StatusOK, s.policy.Decide(r.Context(), in))
}

// AccessMatrix answers, for every team and model, whether a request at the
// given data class would be allowed.
func (s *Server) AccessMatrix(ctx context.Context, dataClass string) map[string]map[string]policy.Decision {
	rt := s.runtime()
	out := map[string]map[string]policy.Decision{}
	for _, t := range rt.estate.Teams {
		out[t.Name] = map[string]policy.Decision{}
		for _, m := range rt.estate.Models {
			out[t.Name][m.Name] = s.policy.Decide(ctx, policy.Input{Subject: policy.Subject{Team: t.Name},
				Action: policy.ActionModel, Resource: policy.Resource{Name: m.Name}, DataClass: dataClass})
		}
	}
	return out
}

func (s *Server) testGuardrails(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Team      string `json:"team"`
		Direction string `json:"direction"`
		Text      string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	dir := estate.Direction(req.Direction)
	if dir != estate.Inbound && dir != estate.Outbound {
		jsonError(w, http.StatusBadRequest, "direction must be inbound or outbound")
		return
	}
	out, err := s.runtime().guardrails.Inspect(r.Context(), req.Team, dir, []string{req.Text})
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	text := ""
	if len(out.Texts) == 1 {
		text = out.Texts[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked": out.Blocked, "reason": out.Reason, "findings": out.Findings, "text": text})
}

func (s *Server) gatewayConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Write(s.runtime().gateway)
}
