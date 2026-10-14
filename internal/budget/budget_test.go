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

package budget

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/store"
)

func TestWindows(t *testing.T) {
	tue := time.Date(2026, 10, 13, 15, 4, 5, 0, time.UTC) // a Tuesday
	cases := []struct {
		p     estate.Period
		start time.Time
		end   time.Time
	}{
		{estate.Day, time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)},
		{estate.Week, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)},
		{estate.Month, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		if s := WindowStart(c.p, tue); !s.Equal(c.start) {
			t.Errorf("%s start = %v", c.p, s)
		}
		if e := WindowEnd(c.p, tue); !e.Equal(c.end) {
			t.Errorf("%s end = %v", c.p, e)
		}
	}
	sun := time.Date(2026, 10, 18, 23, 0, 0, 0, time.UTC)
	if s := WindowStart(estate.Week, sun); !s.Equal(time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("sunday belongs to the week starting monday: %v", s)
	}
	nyc := time.Date(2026, 10, 31, 22, 0, 0, 0, time.FixedZone("EDT", -4*3600)) // Nov 1 02:00 UTC
	if s := WindowStart(estate.Month, nyc); s.Month() != time.November {
		t.Errorf("windows are UTC: %v", s)
	}
}

const src = `
provider p { type openai }
model m { provider p, approved true, cost-in 1 usd/mtok, cost-out 1 usd/mtok }
team t { models [m], budget 10 usd/month, rate 1000 tokens/min, 5 requests/min }
app a { team t, budget 2 usd/day, key-budget 1 usd/day }
app b { team t }
`

func setup(t *testing.T) (*Limiter, *estate.Estate, *time.Time) {
	e, err := cdl.Compile("b.cdl", src)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	l := New(store.NewMemory()).WithClock(func() time.Time { return now })
	return l, e, &now
}

func TestBudgets(t *testing.T) {
	l, e, now := setup(t)
	ctx := context.Background()
	key1 := Subject{Team: "t", App: "a", Key: "k1"}
	key2 := Subject{Team: "t", App: "a", Key: "k2"}

	if err := check(l, ctx, e, key1, 10); err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, e, key1, nil, 1.0, 10, 0)
	// key1 has hit its 1 USD/day key budget; key2 has not.
	var ex *Exceeded
	if err := check(l, ctx, e, key1, 10); !errors.As(err, &ex) || ex.Scope != "key" || ex.Kind != "budget" {
		t.Fatalf("key budget: %v", err)
	}
	if ex.RetryAfter != 12*time.Hour {
		t.Fatalf("retry after = %v", ex.RetryAfter)
	}
	if err := check(l, ctx, e, key2, 10); err != nil {
		t.Fatal(err)
	}
	l.Record(ctx, e, key2, nil, 1.0, 10, 0)
	// app a: 2 USD/day used.
	if err := check(l, ctx, e, Subject{Team: "t", App: "a", Key: "k3"}, 10); !errors.As(err, &ex) || ex.Scope != "app" {
		t.Fatalf("app budget: %v", err)
	}
	// Next day the app and key budgets reset; the team's month budget doesn't.
	*now = now.Add(24 * time.Hour)
	if err := check(l, ctx, e, key1, 10); err != nil {
		t.Fatalf("new day: %v", err)
	}
	l.Record(ctx, e, Subject{Team: "t", App: "b"}, nil, 8.0, 10, 0)
	if err := check(l, ctx, e, Subject{Team: "t", App: "b"}, 10); !errors.As(err, &ex) || ex.Scope != "team" {
		t.Fatalf("team budget: %v", err)
	}

	st, err := l.Statuses(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if st[0].Scope != "team" || st[0].UsedUSD != 10 || st[0].Fraction() != 1 {
		t.Fatalf("statuses = %+v", st)
	}
}

func TestRateLimits(t *testing.T) {
	l, e, now := setup(t)
	ctx := context.Background()
	s := Subject{Team: "t", App: "b"}
	for i := 0; i < 5; i++ {
		if err := check(l, ctx, e, s, 100); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	var ex *Exceeded
	if err := check(l, ctx, e, s, 1); !errors.As(err, &ex) || ex.Kind != "rate" || ex.Limit != "5 requests/min" {
		t.Fatalf("request rate: %v", err)
	}
	*now = now.Add(61 * time.Second)
	if err := check(l, ctx, e, s, 900); err != nil {
		t.Fatalf("after window: %v", err)
	}
	if err := check(l, ctx, e, s, 200); !errors.As(err, &ex) || ex.Limit != "1000 tokens/min" {
		t.Fatalf("token rate: %v", err)
	}
	// Actual usage was far below the estimate: the correction frees capacity.
	l.Record(ctx, e, s, nil, 0, 100, -800)
	if err := check(l, ctx, e, s, 200); err != nil {
		t.Fatalf("after correction: %v", err)
	}
}

func TestRefusedRequestReservesNothing(t *testing.T) {
	l, e, _ := setup(t)
	ctx := context.Background()
	s := Subject{Team: "t", App: "b"}
	if err := check(l, ctx, e, s, 5000); err == nil {
		t.Fatal("over the token rate")
	}
	for i := 0; i < 5; i++ {
		if err := check(l, ctx, e, s, 1); err != nil {
			t.Fatalf("refused request must not consume request quota: %v", err)
		}
	}
}

func check(l *Limiter, ctx context.Context, e *estate.Estate, s Subject, tokens int64) error {
	_, err := l.Check(ctx, e, s, tokens, 0)
	return err
}

// Regression: concurrent requests used to be admitted against the same
// remaining budget, overshooting it by the sum of their costs.
func TestConcurrentRequestsCannotOvershoot(t *testing.T) {
	l, e, now := setup(t)
	ctx := context.Background()
	s := Subject{Team: "t", App: "a"} // app a: 2 USD/day
	var admitted []*Reservation
	for i := 0; i < 100; i++ {
		res, err := l.Check(ctx, e, s, 1, 0.5)
		if err == nil {
			admitted = append(admitted, res)
		}
	}
	if len(admitted) != 4 {
		t.Fatalf("admitted %d requests of 0.50 USD against a 2 USD budget", len(admitted))
	}
	// Settling for less than estimated frees the difference.
	for _, r := range admitted {
		l.Record(ctx, e, s, r, 0.25, 10, 0)
	}
	again, err := l.Check(ctx, e, s, 1, 0.5)
	if err != nil {
		t.Fatalf("after settling at half the estimate there is room again: %v", err)
	}
	l.Release(again)
	// Released reservations leave no residue. (Step past the team's
	// 5 requests/min limit first: this is about money, not rate.)
	*now = now.Add(61 * time.Second)
	r, _ := l.Check(ctx, e, Subject{Team: "t", App: "b"}, 1, 9.0)
	l.Release(r)
	if _, err := l.Check(ctx, e, Subject{Team: "t", App: "b"}, 1, 9.0); err != nil {
		t.Fatalf("released reservation still held: %v", err)
	}
}
