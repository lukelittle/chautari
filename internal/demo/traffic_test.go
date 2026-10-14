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

package demo

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/dataplane"
	"github.com/lukelittle/chautari/internal/mockllm"
	"github.com/lukelittle/chautari/internal/server"
	"github.com/lukelittle/chautari/internal/store"
)

// The demo traffic must exercise every decision the UI shows, against the
// estate it was written for.
func TestTrafficCoversEveryDecision(t *testing.T) {
	mock := httptest.NewServer(mockllm.New(mockllm.Options{}))
	defer mock.Close()
	e, err := cdl.LoadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	adapter, _ := dataplane.New("direct", dataplane.Options{BaseURL: mock.URL + "/v1", MCPURL: mock.URL + "/mcp", A2AURL: mock.URL})
	st := store.NewMemory()
	srv, err := server.New(context.Background(), server.Config{Estate: e, Store: st, Adapter: adapter, AdminToken: "demo-token-123",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	if err := Run(context.Background(), Options{Server: hs.URL, AdminToken: "demo-token-123", Rate: 200, Duration: 1500 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // let in-flight requests land

	recs, _ := st.ListAudit(context.Background(), audit.Query{})
	seen := map[string]map[string]bool{}
	for _, r := range recs {
		if seen[r.Kind] == nil {
			seen[r.Kind] = map[string]bool{}
		}
		seen[r.Kind][r.Decision] = true
	}
	for _, d := range []string{audit.Allow, audit.Deny, audit.Block, audit.Redact} {
		if !seen[audit.KindRequest][d] {
			t.Errorf("no %s request decisions in %d records", d, len(recs))
		}
	}
	if !seen[audit.KindTool][audit.Allow] || !seen[audit.KindTool][audit.Deny] {
		t.Errorf("tool decisions = %v", seen[audit.KindTool])
	}
	if !seen[audit.KindAgent][audit.Allow] {
		t.Errorf("agent decisions = %v", seen[audit.KindAgent])
	}
	en, err := st.GetEntry(context.Background(), "model", "mistral-large")
	if err != nil || en.Status != "reviewed" || en.RequestedBy == en.ReviewedBy {
		t.Fatalf("staged request = %+v %v", en, err)
	}
	if res := audit.Verify(recs); !res.OK {
		t.Fatalf("chain under concurrent load: %+v", res)
	}
}
