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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/dataplane"
	"github.com/lukelittle/chautari/internal/policy"
)

// proxyTo returns a reverse proxy that swaps the caller's key for the
// internal gateway key and stamps identity headers the gateway can trust.
func (s *Server) proxyTo(target *url.URL, c caller, rewritePath string) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			if p, err := url.PathUnescape(rewritePath); err == nil {
				pr.Out.URL.Path, pr.Out.URL.RawPath = p, rewritePath
			}
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-Api-Key")
			pr.Out.Header.Del(dataplane.HeaderTeam)
			pr.Out.Header.Del(dataplane.HeaderApp)
			if k := s.internalKey(); k != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+k)
			}
			pr.Out.Header.Set(dataplane.HeaderTeam, c.team.Name)
			pr.Out.Header.Set(dataplane.HeaderApp, c.app.Name)
		},
		FlushInterval: -1, // MCP and A2A stream over SSE
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("proxy error", "err", err, "target", target.String())
			http.Error(w, "Chautari: data plane unreachable", http.StatusBadGateway)
		},
	}
}

// internalKey is exposed by adapters that know it.
func (s *Server) internalKey() string {
	type keyed interface{ InternalKey() string }
	if k, ok := s.cfg.Adapter.(keyed); ok {
		return k.InternalKey()
	}
	return ""
}

func rpcError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, //nolint:errcheck
		"error": map[string]any{"code": code, "message": msg}})
}

// resolveTool maps a (possibly target-prefixed) MCP tool name to the tool
// server that owns it. agentgateway prefixes tool names with the target name
// when it multiplexes several servers.
func resolveTool(rt *runtime, name string) (server, tool string) {
	var approved []string
	for _, t := range rt.estate.Tools {
		if rt.approvals.Tools[t.Name] {
			approved = append(approved, t.Name)
			if strings.HasPrefix(name, t.Name+"_") {
				return t.Name, strings.TrimPrefix(name, t.Name+"_")
			}
		}
	}
	if len(approved) == 1 {
		return approved[0], name
	}
	return "", name
}

// mcp proxies MCP (Streamable HTTP) to the data plane. Every POST is parsed
// strictly; tools/call is decided and audited here as well as in the gateway
// (defence in depth, and the trail auditors need), and what is forwarded is
// the re-encoded message that was decided on, never the raw bytes.
func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt := s.runtime()
	c, err := s.authenticate(ctx, r, rt)
	if err != nil {
		s.authError(w, err)
		return
	}
	target := s.cfg.Adapter.MCPTarget()
	if target == "" {
		http.Error(w, "Chautari: the "+s.cfg.Adapter.Name()+" data plane does not route MCP; use /v1/tools/authorize", http.StatusNotImplemented)
		return
	}
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "Chautari: bad MCP target", http.StatusInternalServerError)
		return
	}
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(raw) > maxBody {
			http.Error(w, "Chautari: body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		msg, err := parseRPC(raw)
		if err != nil {
			rpcError(w, nil, -32600, "Chautari: invalid JSON-RPC message: "+err.Error())
			return
		}
		if msg.Method == "tools/call" {
			name, _ := msg.toolName()
			server, tool := resolveTool(rt, name)
			dc := s.dataClass(r, c, rt)
			if server == "" {
				if !s.mustAudit(w, ctx, audit.Record{Kind: audit.KindTool, Actor: c.key.ID, Subject: c.team.Name + "/" + c.app.Name,
					Action: policy.ActionTool, Resource: "tool/?/" + name, Decision: audit.Deny,
					Reasons: []string{"tool does not belong to an approved tool server"}, Details: map[string]any{"via": "mcp", "data_class": dc}}) {
					return
				}
				rpcError(w, msg.ID, -32001, "Chautari policy: tool "+name+" does not belong to an approved tool server")
				return
			}
			d, ok := s.decideTool(w, ctx, c, server, tool, dc, "mcp")
			if !ok {
				return
			}
			if !d.Allow {
				rpcError(w, msg.ID, -32001, "Chautari policy: "+strings.Join(d.Reasons, "; "))
				return
			}
		}
		body := msg.canonical()
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	s.proxyTo(u, c, u.Path).ServeHTTP(w, r)
}

// a2aRest validates the path below /a2a/<agent>/. Encoded slashes and dot
// segments are refused: the request was authorised for one agent and must
// not be able to walk to another.
func a2aRest(r *http.Request, agent string) (string, bool) {
	esc := r.URL.EscapedPath()
	prefix := "/a2a/" + url.PathEscape(agent)
	if !strings.HasPrefix(esc, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(esc, prefix)
	lower := strings.ToLower(rest)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") || strings.Contains(rest, "\\") {
		return "", false
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return strings.TrimPrefix(rest, "/"), true
}

// a2a proxies agent-to-agent traffic to the agent's data plane route.
func (s *Server) a2a(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt := s.runtime()
	c, err := s.authenticate(ctx, r, rt)
	if err != nil {
		s.authError(w, err)
		return
	}
	agent := r.PathValue("agent")
	rest, ok := a2aRest(r, agent)
	if !ok {
		http.Error(w, "Chautari: invalid agent path", http.StatusBadRequest)
		return
	}
	dc := s.dataClass(r, c, rt)
	d := s.policy.Decide(ctx, policy.Input{
		Subject:   policy.Subject{Team: c.team.Name, App: c.app.Name, Key: c.key.ID},
		Action:    policy.ActionAgent,
		Resource:  policy.Resource{Name: agent},
		DataClass: dc,
	})
	decision := audit.Allow
	if !d.Allow {
		decision = audit.Deny
	}
	if !s.mustAudit(w, ctx, audit.Record{Kind: audit.KindAgent, Actor: c.key.ID, Subject: c.team.Name + "/" + c.app.Name,
		Action: policy.ActionAgent, Resource: "agent/" + agent, Decision: decision, Reasons: d.Reasons,
		Details: map[string]any{"method": r.Method, "path": "/" + rest, "data_class": dc}}) {
		return
	}
	if !d.Allow {
		http.Error(w, "Chautari policy: "+strings.Join(d.Reasons, "; "), http.StatusForbidden)
		return
	}
	target := s.cfg.Adapter.A2ATarget(agent)
	if target == "" {
		http.Error(w, "Chautari: the "+s.cfg.Adapter.Name()+" data plane does not route A2A", http.StatusNotImplemented)
		return
	}
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "Chautari: bad A2A target", http.StatusInternalServerError)
		return
	}
	s.proxyTo(u, c, strings.TrimSuffix(u.Path, "/")+"/"+rest).ServeHTTP(w, r)
}
