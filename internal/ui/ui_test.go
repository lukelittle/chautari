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

package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Result()
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIndexAtRootAndDeepPaths(t *testing.T) {
	h := Handler()
	want, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/overview", "/some/deep/client/path", "/index.html"} {
		r := get(t, h, p)
		if r.StatusCode != 200 {
			t.Fatalf("%s: status %d", p, r.StatusCode)
		}
		if ct := r.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("%s: content type %q", p, ct)
		}
		csp := r.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("%s: CSP %q", p, csp)
		}
		if r.Header.Get("Cache-Control") == "" {
			t.Errorf("%s: no Cache-Control", p)
		}
		if body(t, r) != string(want) {
			t.Errorf("%s: body is not index.html", p)
		}
	}
}

func TestAssets(t *testing.T) {
	h := Handler()
	cases := map[string]string{
		"/assets/app.css":           "text/css; charset=utf-8",
		"/assets/app.js":            "text/javascript; charset=utf-8",
		"/assets/views/overview.js": "text/javascript; charset=utf-8",
		"/assets/favicon.svg":       "image/svg+xml",
	}
	for p, ct := range cases {
		r := get(t, h, p)
		if r.StatusCode != 200 {
			t.Fatalf("%s: status %d", p, r.StatusCode)
		}
		if got := r.Header.Get("Content-Type"); got != ct {
			t.Errorf("%s: content type %q, want %q", p, got, ct)
		}
		if r.Header.Get("Cache-Control") == "" || r.Header.Get("ETag") == "" {
			t.Errorf("%s: missing caching headers", p)
		}
		if r.Header.Get("Content-Security-Policy") != "" {
			t.Errorf("%s: CSP belongs on the document only", p)
		}
	}
	// Revalidation is a cheap 304.
	r := get(t, h, "/assets/app.css")
	req := httptest.NewRequest(http.MethodGet, "/assets/app.css", nil)
	req.Header.Set("If-None-Match", r.Header.Get("ETag"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("If-None-Match: status %d", rec.Code)
	}
	if r := get(t, h, "/assets/nope.js"); r.StatusCode != 404 {
		t.Errorf("missing asset: status %d", r.StatusCode)
	}
	if r := get(t, h, "/api/nope"); r.StatusCode != 404 || !strings.Contains(r.Header.Get("Content-Type"), "json") {
		t.Errorf("unknown API path must not get the app shell: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: status %d", rec.Code)
	}
}

var (
	scriptTag = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	refAttr   = regexp.MustCompile(`(?i)\b(?:src|href)="(/assets/[^"]+)"`)
	styleAttr = regexp.MustCompile(`(?i)<[^>]+\sstyle=`)
	importRe  = regexp.MustCompile(`(?m)(?:^|\s)(?:import|from)\s*\(?\s*"(\.{1,2}/[^"]+)"`)
)

func TestNoInlineScriptsOrStyles(t *testing.T) {
	b := body(t, get(t, Handler(), "/"))
	for _, m := range scriptTag.FindAllStringSubmatch(b, -1) {
		if strings.TrimSpace(m[2]) != "" {
			t.Errorf("inline script body: %q", m[2])
		}
		if !strings.Contains(m[1], "src=") {
			t.Errorf("script without src: %s", m[0])
		}
	}
	if strings.Contains(b, "<style") || styleAttr.MatchString(b) {
		t.Error("index.html has inline styles")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+=`).MatchString(b) {
		t.Error("index.html has inline event handlers")
	}
}

func TestReferencedAssetsExist(t *testing.T) {
	h := Handler()
	b := body(t, get(t, h, "/"))
	refs := refAttr.FindAllStringSubmatch(b, -1)
	if len(refs) < 3 {
		t.Fatalf("expected stylesheet, script and icon references, got %v", refs)
	}
	seen := map[string]bool{}
	var walk func(string)
	walk = func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		r := get(t, h, p)
		if r.StatusCode != 200 {
			t.Errorf("%s: status %d", p, r.StatusCode)
			return
		}
		if !strings.HasSuffix(p, ".js") {
			return
		}
		// Follow static and dynamic module imports so every view is covered.
		for _, m := range importRe.FindAllStringSubmatch(body(t, r), -1) {
			walk(filepath.ToSlash(filepath.Join(filepath.Dir(p), m[1])))
		}
	}
	for _, m := range refs {
		walk(m[1])
	}
	for _, v := range []string{"overview", "estate", "approvals", "keys", "guardrails", "spend", "audit", "controls"} {
		if !seen["/assets/views/"+v+".js"] {
			t.Errorf("view %s is not reachable from index.html", v)
		}
	}
}

// No module may hand server data to innerHTML.
func TestNoInnerHTML(t *testing.T) {
	err := filepath.Walk("static", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".js") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s uses %s", p, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
