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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Admin identity.
//
// Two modes. With per-person tokens (CHAUTARI_ADMIN_TOKENS), the token says
// who you are and separation of duties is enforced. With a single shared
// token (CHAUTARI_ADMIN_TOKEN, fine for a demo), people name themselves and
// separation of duties is advisory: the audit log and the controls report say
// so. OIDC replaces both.

// adminIdentity is an authenticated administrator.
type adminIdentity struct {
	Actor    string // who; empty when a shared token was used without a name
	Verified bool   // true when the identity comes from the credential itself
	Session  bool   // authenticated by session cookie (CSRF rules apply)
}

const (
	cookieName      = "chautari_session"
	sessionLifetime = 12 * time.Hour
)

// matchToken compares a presented token with the configured ones in
// constant time and returns the identity it belongs to.
func (s *Server) matchToken(tok string) (adminIdentity, bool) {
	if tok == "" {
		return adminIdentity{}, false
	}
	h := sha256.Sum256([]byte(tok))
	var found adminIdentity
	ok := false
	// Check every token, always, so timing doesn't reveal which matched.
	for _, name := range s.adminNames {
		t := sha256.Sum256([]byte(s.cfg.AdminTokens[name]))
		if subtle.ConstantTimeCompare(h[:], t[:]) == 1 {
			found, ok = adminIdentity{Actor: name, Verified: true}, true
		}
	}
	if s.cfg.AdminToken != "" {
		t := sha256.Sum256([]byte(s.cfg.AdminToken))
		if subtle.ConstantTimeCompare(h[:], t[:]) == 1 && !ok {
			found, ok = adminIdentity{}, true
		}
	}
	return found, ok
}

// admin authenticates an admin request by bearer token or session cookie.
func (s *Server) adminAuth(r *http.Request) (adminIdentity, bool) {
	if tok := bearer(r); tok != "" {
		id, ok := s.matchToken(tok)
		if ok && !id.Verified {
			id.Actor = strings.TrimSpace(r.Header.Get("X-Chautari-Actor"))
		}
		return id, ok
	}
	if c, err := r.Cookie(cookieName); err == nil {
		if id, ok := s.parseSession(c.Value); ok {
			id.Session = true
			return id, true
		}
	}
	return adminIdentity{}, false
}

// sessionKey signs session cookies. It is derived from every configured
// token, so rotating a token signs everyone out.
func (s *Server) sessionKey() []byte {
	h := sha256.New()
	h.Write([]byte("chautari/session/v1\x00" + s.cfg.AdminToken))
	for _, n := range s.adminNames {
		h.Write([]byte("\x00" + n + "=" + s.cfg.AdminTokens[n]))
	}
	return h.Sum(nil)
}

// newSession returns a signed cookie value: v1.<actor>.<verified>.<expiry>.<mac>.
// The token itself never goes into the cookie.
func (s *Server) newSession(id adminIdentity) string {
	payload := fmt.Sprintf("v1.%s.%t.%d", base64.RawURLEncoding.EncodeToString([]byte(id.Actor)), id.Verified, s.now().Add(sessionLifetime).Unix())
	m := hmac.New(sha256.New, s.sessionKey())
	m.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(m.Sum(nil))
}

func (s *Server) parseSession(v string) (adminIdentity, bool) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return adminIdentity{}, false
	}
	payload, mac := v[:i], v[i+1:]
	m := hmac.New(sha256.New, s.sessionKey())
	m.Write([]byte(payload))
	want := hex.EncodeToString(m.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(mac), []byte(want)) != 1 {
		return adminIdentity{}, false
	}
	parts := strings.Split(payload, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return adminIdentity{}, false
	}
	actor, err := base64.RawURLEncoding.DecodeString(parts[1])
	exp, err2 := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || err2 != nil || s.now().Unix() > exp {
		return adminIdentity{}, false
	}
	return adminIdentity{Actor: string(actor), Verified: parts[2] == "true"}, true
}

// loginLimiter throttles failed sign-ins per client address.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	loginWindow   = 5 * time.Minute
	loginFailures = 10
)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (l *loginLimiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.failures[ip][:0]
	for _, t := range l.failures[ip] {
		if now.Sub(t) < loginWindow {
			recent = append(recent, t)
		}
	}
	l.failures[ip] = recent
	return len(recent) >= loginFailures
}

func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[ip] = append(l.failures[ip], now)
}

// parseAdminTokens reads "name=token,name=token".
func parseAdminTokens(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, tok, ok := strings.Cut(part, "=")
		name, tok = strings.TrimSpace(name), strings.TrimSpace(tok)
		if !ok || name == "" || tok == "" {
			return nil, fmt.Errorf("admin tokens must look like name=token[,name=token]")
		}
		if len(tok) < 16 {
			return nil, fmt.Errorf("admin token for %s is shorter than 16 characters", name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("admin %s is listed twice", name)
		}
		out[name] = tok
	}
	return out, nil
}

// ParseAdminTokens is exported for the CLI.
func ParseAdminTokens(spec string) (map[string]string, error) { return parseAdminTokens(spec) }

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
