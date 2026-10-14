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

// Package server is Chautari's HTTP surface: the checkpoint every AI request
// passes through (/v1, /mcp, /a2a), the admin API (/api) and the admin UI.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/budget"
	"github.com/lukelittle/chautari/internal/dataplane"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/guardrails"
	"github.com/lukelittle/chautari/internal/policy"
	"github.com/lukelittle/chautari/internal/registry"
	"github.com/lukelittle/chautari/internal/store"
)

// Config wires a server together.
type Config struct {
	Estate  *estate.Estate
	Store   store.Store
	Adapter dataplane.Adapter
	// AdminToken is a single shared admin token (people name themselves).
	AdminToken string
	// AdminTokens maps each administrator to a personal token. When set,
	// the token establishes who is acting and separation of duties holds.
	AdminTokens map[string]string
	// GatewayConfigPath, if set, is where the live data plane config is
	// written whenever registry state changes.
	GatewayConfigPath string
	PolicyDir         string
	Bedrock           guardrails.BedrockClient
	Logger            *slog.Logger
	// ResyncInterval re-reads registry state from the store so replicas
	// converge on changes made elsewhere. Zero means 15 seconds.
	ResyncInterval time.Duration
	Version        string
	Now            func() time.Time
	// UI serves the admin interface at /. Nil disables it.
	UI http.Handler
	// DigestKey keys the HMAC of prompts recorded in the audit log. Empty
	// derives one from the admin token.
	DigestKey string
}

// runtime is everything derived from estate + registry state. It is swapped
// atomically on reload so requests always see a consistent view.
type runtime struct {
	estate     *estate.Estate // CDL estate plus API-registered models
	status     map[string]string
	approvals  registry.Approvals
	guardrails *guardrails.Engine
	gateway    []byte // last rendered data plane config
}

// Server is the control plane.
type Server struct {
	cfg        Config
	log        *slog.Logger
	audit      *audit.Log
	registry   *registry.Registry
	policy     *policy.Engine
	limiter    *budget.Limiter
	rt         atomic.Pointer[runtime]
	reloadMu   sync.Mutex
	now        func() time.Time
	started    time.Time
	digestKey  []byte
	adminNames []string
	logins     *loginLimiter
}

// New builds a server: it seeds the registry from the estate, compiles
// policy, renders the data plane config and records all of it in the audit log.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Estate == nil || cfg.Store == nil || cfg.Adapter == nil {
		return nil, errors.New("server: estate, store and adapter are required")
	}
	if len(cfg.AdminTokens) == 0 && len(cfg.AdminToken) < 8 {
		return nil, errors.New("server: set per-person admin tokens, or a shared admin token of at least 8 characters")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ResyncInterval == 0 {
		cfg.ResyncInterval = 15 * time.Second
	}
	s := &Server{cfg: cfg, log: cfg.Logger, now: cfg.Now}
	dk := cfg.DigestKey
	if dk == "" {
		dk = "chautari/prompt-digest/v1/" + cfg.AdminToken
	}
	sum := sha256.Sum256([]byte(dk))
	s.digestKey = sum[:]
	s.adminNames = sortedNames(cfg.AdminTokens)
	s.logins = &loginLimiter{failures: map[string][]time.Time{}}
	s.started = s.now()
	s.audit = audit.NewLog(cfg.Store).WithClock(cfg.Now)
	s.limiter = budget.New(cfg.Store).WithClock(cfg.Now)
	var err error
	if s.policy, err = policy.New(cfg.PolicyDir); err != nil {
		return nil, err
	}
	s.registry = registry.New(cfg.Store, s.audit, nil).WithClock(cfg.Now)

	if _, err := s.audit.Write(ctx, audit.Record{
		Kind: audit.KindConfig, Actor: cfg.Estate.Source.Actor(), Action: "estate.load", Resource: "estate/" + cfg.Estate.Name,
		Decision: audit.NA, Details: map[string]any{
			"cdl_file": cfg.Estate.Source.File, "cdl_sha256": cfg.Estate.Source.SHA256, "estate_digest": cfg.Estate.Digest(),
			"version": cfg.Version, "dataplane": cfg.Adapter.Name(),
		},
	}); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if _, err := s.registry.Seed(ctx, cfg.Estate); err != nil {
		return nil, fmt.Errorf("seed registry: %w", err)
	}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload recomputes the runtime from the estate and the registry, recompiles
// policy and re-renders the data plane config if it changed.
func (s *Server) Reload(ctx context.Context) error {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	entries, err := s.registry.List(ctx, "")
	if err != nil {
		return err
	}
	est := registry.MergeAPIModels(s.cfg.Estate, entries)
	status := map[string]string{}
	for _, e := range entries {
		status[e.Kind+"/"+e.Name] = e.Status
	}
	approvals, err := s.registry.Approvals(ctx)
	if err != nil {
		return err
	}
	if err := s.policy.Load(est, func(kind, name string) string { return status[kind+"/"+name] }); err != nil {
		return err
	}
	g, err := guardrails.New(est, s.cfg.Bedrock)
	if err != nil {
		return err
	}
	rt := &runtime{estate: est, status: status, approvals: approvals, guardrails: g}

	files, err := s.cfg.Adapter.Render(est, dataplane.State{Models: approvals.Models, Tools: approvals.Tools, Agents: approvals.Agents})
	if err != nil {
		return fmt.Errorf("render data plane config: %w", err)
	}
	if len(files) > 0 {
		rt.gateway = files[0].Content
	}
	prev := s.rt.Load()
	s.rt.Store(rt)
	if prev == nil || !bytes.Equal(prev.gateway, rt.gateway) {
		if err := s.writeGateway(ctx, rt.gateway); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) writeGateway(ctx context.Context, content []byte) error {
	if s.cfg.GatewayConfigPath == "" || len(content) == 0 {
		return nil
	}
	if cur, err := os.ReadFile(s.cfg.GatewayConfigPath); err == nil && bytes.Equal(cur, content) {
		return nil // another replica, or a previous run, already wrote it
	}
	// Write-then-rename so the gateway never reads a half-written file.
	dir := filepath.Dir(s.cfg.GatewayConfigPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gateway-*.yaml")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	os.Chmod(tmp.Name(), 0o644) //nolint:errcheck
	if err := os.Rename(tmp.Name(), s.cfg.GatewayConfigPath); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	sum := sha256.Sum256(content)
	s.log.Info("data plane config rendered", "path", s.cfg.GatewayConfigPath, "sha256", hex.EncodeToString(sum[:8]))
	_, err = s.audit.Write(ctx, audit.Record{Kind: audit.KindConfig, Actor: "chautari", Action: "gateway.render",
		Resource: "dataplane/" + s.cfg.Adapter.Name(), Decision: audit.NA,
		Details: map[string]any{"sha256": hex.EncodeToString(sum[:]), "path": s.cfg.GatewayConfigPath}})
	return err
}

// Run resyncs registry state until ctx ends, so that changes made through
// another replica reach this one's policy engine and data plane.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.ResyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Reload(ctx); err != nil {
				s.log.Error("resync failed", "err", err)
			}
		}
	}
}

func (s *Server) runtime() *runtime { return s.rt.Load() }

// Handler returns the full HTTP surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", s.ready)

	// Checkpoint
	mux.HandleFunc("POST /v1/chat/completions", s.chatCompletions)
	mux.HandleFunc("GET /v1/models", s.models)
	mux.HandleFunc("POST /v1/tools/authorize", s.authorizeTool)
	mux.HandleFunc("/mcp", s.mcp)
	mux.HandleFunc("/a2a/{agent}/{rest...}", s.a2a)
	mux.HandleFunc("/a2a/{agent}", s.a2a)

	// Admin API
	s.adminRoutes(mux)
	if s.cfg.UI != nil {
		mux.Handle("/", s.cfg.UI)
	}
	return s.middleware(mux)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	type pinger interface{ Ping(context.Context) error }
	if p, ok := s.cfg.Store.(pinger); ok {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := p.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.Write([]byte("ready\n"))
}

// statusWriter records the status code for access logs.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic", "err", rec, "path", r.URL.Path)
				http.Error(sw, "internal error", http.StatusInternalServerError)
			}
			if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
				s.log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds())
			}
		}()
		next.ServeHTTP(sw, r)
	})
}
