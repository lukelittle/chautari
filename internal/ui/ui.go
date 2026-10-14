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

// Package ui is Chautari's admin interface: a small single-page app written
// in plain HTML, CSS and JavaScript modules, embedded in the binary so the
// control plane serves it with no build step and no network access.
//
// The app talks only to the admin API under /api. Every page is reachable
// from index.html through hash routes (#/overview, #/audit, …), so the server
// answers any path that is not an asset with the same document.
package ui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed static
var static embed.FS

// ContentSecurityPolicy is sent with index.html. Scripts and styles come only
// from this origin; nothing is inlined.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".svg":  "image/svg+xml",
	".png":  "image/png",
	".ico":  "image/x-icon",
	".json": "application/json",
	".txt":  "text/plain; charset=utf-8",
}

type file struct {
	body  []byte
	ctype string
	etag  string
}

// Handler serves the admin UI. Mount it at "/" beneath the API routes.
func Handler() http.Handler {
	files := map[string]file{}
	root, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error { //nolint:errcheck
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		ct, ok := contentTypes[path.Ext(p)]
		if !ok {
			ct = "application/octet-stream"
		}
		sum := sha256.Sum256(b)
		files["/"+p] = file{body: b, ctype: ct, etag: `"` + hex.EncodeToString(sum[:8]) + `"`}
		return nil
	})
	index, ok := files["/index.html"]
	if !ok {
		panic("ui: index.html missing from embed")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		// Unknown API paths are API errors, not the app shell.
		for _, pre := range []string{"/api/", "/v1/", "/mcp/", "/a2a/"} {
			if strings.HasPrefix(p+"/", pre) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"error":"not found"}` + "\n")) //nolint:errcheck
				return
			}
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(p, "/assets/") {
			f, ok := files[p]
			if !ok {
				http.NotFound(w, r)
				return
			}
			// Asset names are not content-hashed, so browsers revalidate
			// every load; the ETag makes that a cheap 304.
			h.Set("Content-Type", f.ctype)
			h.Set("Cache-Control", "no-cache")
			h.Set("ETag", f.etag)
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(f.body))
			return
		}
		if p == "/favicon.ico" {
			http.Redirect(w, r, "/assets/favicon.svg", http.StatusMovedPermanently)
			return
		}
		h.Set("Content-Type", index.ctype)
		h.Set("Cache-Control", "no-cache")
		h.Set("ETag", index.etag)
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(index.body))
	})
}
