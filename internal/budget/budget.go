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

// Package budget enforces spend budgets and token/request rate limits per
// team, app and API key.
//
// Spend is persisted in calendar windows (UTC day, ISO week, month) so it
// survives restarts and is shared by replicas. Rate limits are sliding
// one-minute or one-hour windows held in memory, per replica.
package budget

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/store"
)

// Periods spend is always recorded over, whether or not a budget exists, so
// dashboards have data from day one.
var Periods = []estate.Period{estate.Day, estate.Week, estate.Month}

// WindowStart returns the start of the calendar window containing t.
func WindowStart(p estate.Period, t time.Time) time.Time {
	t = t.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	switch p {
	case estate.Week:
		offset := (int(day.Weekday()) + 6) % 7 // Monday = 0
		return day.AddDate(0, 0, -offset)
	case estate.Month:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return day
}

// WindowEnd returns the end of the calendar window containing t.
func WindowEnd(p estate.Period, t time.Time) time.Time {
	s := WindowStart(p, t)
	switch p {
	case estate.Week:
		return s.AddDate(0, 0, 7)
	case estate.Month:
		return s.AddDate(0, 1, 0)
	}
	return s.AddDate(0, 0, 1)
}

// Subject is who a request is charged to.
type Subject struct {
	Team, App, Key string
}

// Exceeded explains which limit stopped a request.
type Exceeded struct {
	Kind       string // "budget" or "rate"
	Scope      string // team | app | key
	Name       string
	Limit      string
	Used       string
	RetryAfter time.Duration
}

func (e *Exceeded) Error() string {
	return fmt.Sprintf("%s %s %s exceeded: %s used of %s", e.Scope, e.Name, e.Kind, e.Used, e.Limit)
}

// Limiter checks and records usage.
type Limiter struct {
	store store.Store
	now   func() time.Time

	mu       sync.Mutex
	rates    map[rateKey]*window
	inflight map[store.SpendKey]float64 // estimated cost of admitted, unfinished requests
}

type rateKey struct {
	scope, name string
	unit        estate.RateUnit
	period      estate.Period
}

type event struct {
	at time.Time
	n  int64
}

// window is a sliding log of usage events.
type window struct{ events []event }

func (w *window) sum(since time.Time) int64 {
	i := 0
	for i < len(w.events) && w.events[i].at.Before(since) {
		i++
	}
	w.events = w.events[i:]
	var s int64
	for _, e := range w.events {
		s += e.n
	}
	return s
}

// New returns a limiter.
func New(s store.Store) *Limiter {
	return &Limiter{store: s, now: time.Now, rates: map[rateKey]*window{}, inflight: map[store.SpendKey]float64{}}
}

// WithClock overrides the clock, for tests.
func (l *Limiter) WithClock(now func() time.Time) *Limiter { l.now = now; return l }

func periodDuration(p estate.Period) time.Duration {
	if p == estate.Hour {
		return time.Hour
	}
	return time.Minute
}

type scoped struct {
	scope, name string
	budget      *estate.Budget
	rates       []estate.Rate
}

func scopes(e *estate.Estate, s Subject) []scoped {
	var out []scoped
	if t, ok := e.Team(s.Team); ok {
		out = append(out, scoped{"team", t.Name, t.Budget, t.Rates})
	}
	if a, ok := e.App(s.App); ok {
		out = append(out, scoped{"app", a.Name, a.Budget, a.Rates})
		if s.Key != "" {
			out = append(out, scoped{"key", s.Key, a.KeyBudget, nil})
		}
	}
	return out
}

// Reservation is the estimated cost a request holds against its budgets
// while it runs. Pass it to Record (or Release) when the request ends.
type Reservation struct {
	keys []store.SpendKey
	usd  float64
}

// Check admits or refuses a request expected to use estTokens and cost
// estUSD. Admission reserves the estimate against every budget window and
// rate window, so concurrent requests on this replica cannot together blow
// through a budget; Record settles the actual cost.
func (l *Limiter) Check(ctx context.Context, e *estate.Estate, s Subject, estTokens int64, estUSD float64) (*Reservation, error) {
	now := l.now()
	sc := scopes(e, s)
	type budgeted struct {
		x   scoped
		key store.SpendKey
		usd float64
	}
	var bs []budgeted
	for _, x := range sc {
		if x.budget == nil {
			continue
		}
		k := store.SpendKey{Scope: x.scope, Subject: x.name, Period: string(x.budget.Period), WindowStart: WindowStart(x.budget.Period, now)}
		sp, err := l.store.GetSpend(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("budget lookup: %w", err) // caller fails closed
		}
		bs = append(bs, budgeted{x, k, sp.USD})
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range bs {
		held := l.inflight[b.key]
		if b.usd >= b.x.budget.USD || b.usd+held+estUSD > b.x.budget.USD {
			used := fmt.Sprintf("%.2f USD", b.usd)
			if held > 0 {
				used += fmt.Sprintf(" (+%.2f USD in flight)", held)
			}
			return nil, &Exceeded{Kind: "budget", Scope: b.x.scope, Name: b.x.name,
				Limit: fmt.Sprintf("%.2f USD/%s", b.x.budget.USD, b.x.budget.Period), Used: used,
				RetryAfter: WindowEnd(b.x.budget.Period, now).Sub(now)}
		}
	}
	for _, x := range sc {
		for _, r := range x.rates {
			w := l.window(rateKey{x.scope, x.name, r.Unit, r.Period})
			want := int64(1)
			if r.Unit == estate.Tokens {
				want = estTokens
			}
			used := w.sum(now.Add(-periodDuration(r.Period)))
			if used+want > r.Limit {
				retry := periodDuration(r.Period)
				if len(w.events) > 0 {
					retry = w.events[0].at.Add(periodDuration(r.Period)).Sub(now)
				}
				return nil, &Exceeded{Kind: "rate", Scope: x.scope, Name: x.name, Limit: r.String(),
					Used: fmt.Sprintf("%d %s", used, r.Unit), RetryAfter: retry}
			}
		}
	}
	// Reserve only once every limit has passed.
	res := &Reservation{usd: estUSD}
	for _, b := range bs {
		l.inflight[b.key] += estUSD
		res.keys = append(res.keys, b.key)
	}
	for _, x := range sc {
		for _, r := range x.rates {
			n := int64(1)
			if r.Unit == estate.Tokens {
				n = estTokens
			}
			w := l.window(rateKey{x.scope, x.name, r.Unit, r.Period})
			w.events = append(w.events, event{now, n})
		}
	}
	return res, nil
}

// Release returns a reservation without charging it.
func (l *Limiter) Release(res *Reservation) {
	if res == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range res.keys {
		if l.inflight[k] -= res.usd; l.inflight[k] <= 1e-12 {
			delete(l.inflight, k)
		}
	}
	res.keys = nil
}

func (l *Limiter) window(k rateKey) *window {
	w, ok := l.rates[k]
	if !ok {
		w = &window{}
		l.rates[k] = w
	}
	return w
}

// Record charges actual usage and releases the request's reservation.
// tokenDelta corrects the token rate windows for the difference between
// actual and estimated tokens.
func (l *Limiter) Record(ctx context.Context, e *estate.Estate, s Subject, res *Reservation, usd float64, tokens, tokenDelta int64) error {
	defer l.Release(res)
	now := l.now()
	var keys []store.SpendKey
	for _, x := range scopes(e, s) {
		for _, p := range Periods {
			keys = append(keys, store.SpendKey{Scope: x.scope, Subject: x.name, Period: string(p), WindowStart: WindowStart(p, now)})
		}
	}
	if tokenDelta != 0 {
		l.mu.Lock()
		for _, x := range scopes(e, s) {
			for _, r := range x.rates {
				if r.Unit == estate.Tokens {
					w := l.window(rateKey{x.scope, x.name, r.Unit, r.Period})
					w.events = append(w.events, event{now, tokenDelta})
				}
			}
		}
		l.mu.Unlock()
	}
	return l.store.AddSpend(ctx, keys, usd, tokens)
}

// Status is a budget with its current consumption, for dashboards.
type Status struct {
	Scope    string  `json:"scope"`
	Name     string  `json:"name"`
	Period   string  `json:"period"`
	LimitUSD float64 `json:"limit_usd"`
	UsedUSD  float64 `json:"used_usd"`
	Tokens   int64   `json:"tokens"`
	Requests int64   `json:"requests"`
}

// Fraction is used/limit, or 0 when unlimited.
func (s Status) Fraction() float64 {
	if s.LimitUSD <= 0 {
		return 0
	}
	return s.UsedUSD / s.LimitUSD
}

// Statuses reports every team's and app's spend in its budget window (or the
// current month when it has no budget).
func (l *Limiter) Statuses(ctx context.Context, e *estate.Estate) ([]Status, error) {
	now := l.now()
	var out []Status
	add := func(scope, name string, b *estate.Budget) error {
		p, limit := estate.Month, 0.0
		if b != nil {
			p, limit = b.Period, b.USD
		}
		sp, err := l.store.GetSpend(ctx, store.SpendKey{Scope: scope, Subject: name, Period: string(p), WindowStart: WindowStart(p, now)})
		if err != nil {
			return err
		}
		out = append(out, Status{Scope: scope, Name: name, Period: string(p), LimitUSD: limit, UsedUSD: sp.USD, Tokens: sp.Tokens, Requests: sp.Requests})
		return nil
	}
	for _, t := range e.Teams {
		if err := add("team", t.Name, t.Budget); err != nil {
			return nil, err
		}
	}
	for _, a := range e.Apps {
		if err := add("app", a.Name, a.Budget); err != nil {
			return nil, err
		}
	}
	return out, nil
}
