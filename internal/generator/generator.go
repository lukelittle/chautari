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

// Package generator turns an estate into a deployable tree: gateway config,
// policy bundle, Docker Compose, Helm chart, Terraform for AWS, OpenTelemetry
// and the controls report.
//
// Output is a pure function of the estate and options. Write is idempotent:
// unchanged files are not touched, and files a human edited since the last
// run are left alone unless forced.
package generator

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/lukelittle/chautari/internal/controls"
	"github.com/lukelittle/chautari/internal/dataplane"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/policy"
)

//go:embed all:templates
var templates embed.FS

// Options control generation.
type Options struct {
	// Version is the Chautari release the stack runs, e.g. "0.1.0".
	Version string
	// Image overrides the Chautari container image.
	Image string
	// CDL is the estate source, copied into the output as estate.cdl.
	CDL []byte
	// Demo adds the mock provider and a traffic generator to Compose.
	Demo bool
}

// File is one generated file.
type File struct {
	Path    string
	Content []byte
	Mode    os.FileMode
}

// Data is what templates see.
type Data struct {
	Estate       *estate.Estate
	Name         string // DNS-safe estate name
	Version      string
	Image        string // Chautari image (control plane, mock-llm, CLI)
	GatewayImage string
	Dataplane    string
	Demo         bool
	HasMCP       bool
	HasA2A       bool
	// ProviderEnvs are the provider credential variables the data plane reads.
	ProviderEnvs []string
	// UsesBedrock is true when any provider or guardrail needs AWS Bedrock.
	UsesBedrock bool
	// GatewayConfigFile is the data plane config file name (gateway.yaml or litellm.yaml).
	GatewayConfigFile string
}

var dnsUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// DNSName lowercases and strips a name to [a-z0-9-], max 40 chars.
func DNSName(s string) string {
	n := strings.Trim(dnsUnsafe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(n) > 40 {
		n = strings.TrimRight(n[:40], "-")
	}
	if n == "" {
		n = "chautari"
	}
	return n
}

// NewData derives template data from an estate.
func NewData(e *estate.Estate, opts Options) Data {
	d := Data{
		Estate:            e,
		Name:              DNSName(e.Name),
		Version:           opts.Version,
		Image:             opts.Image,
		GatewayImage:      dataplane.AgentGatewayImage,
		Dataplane:         e.Dataplane,
		Demo:              opts.Demo,
		GatewayConfigFile: "gateway.yaml",
	}
	if d.Version == "" {
		d.Version = "dev"
	}
	if d.Image == "" {
		d.Image = "ghcr.io/lukelittle/chautari:" + d.Version
	}
	if e.Dataplane == "litellm" {
		d.GatewayImage = dataplane.LiteLLMImage
		d.GatewayConfigFile = "litellm.yaml"
	}
	for _, t := range e.Tools {
		if t.Approved {
			d.HasMCP = true
		}
	}
	for _, a := range e.Agents {
		if a.Approved && a.Endpoint != "" {
			d.HasA2A = true
		}
	}
	envs := map[string]bool{}
	for _, p := range e.Providers {
		if p.APIKeyEnv != "" {
			envs[p.APIKeyEnv] = true
		}
		if p.Type == "bedrock" {
			d.UsesBedrock = true
		}
		if p.Type == "vertex" {
			envs["GOOGLE_CLOUD_PROJECT"] = true
		}
	}
	for _, p := range e.Policies {
		if p.BedrockGuardrail != "" {
			d.UsesBedrock = true
		}
	}
	for k := range envs {
		d.ProviderEnvs = append(d.ProviderEnvs, k)
	}
	sort.Strings(d.ProviderEnvs)
	return d
}

var funcs = template.FuncMap{
	"env":   func(s string) string { return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(s)) },
	"quote": func(s string) string { b, _ := json.Marshal(s); return string(b) },
	"indent": func(n int, s string) string {
		pad := strings.Repeat(" ", n)
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		for i, l := range lines {
			if l != "" {
				lines[i] = pad + l
			}
		}
		return strings.Join(lines, "\n")
	},
	"dns":  DNSName,
	"join": strings.Join,
	"usd":  func(f float64) string { return fmt.Sprintf("%.2f", f) },
}

// Generate renders every file for the estate.
func Generate(e *estate.Estate, opts Options) ([]File, error) {
	d := NewData(e, opts)
	var files []File

	// Templates. Delimiters are [[ ]] so Helm's {{ }} pass through untouched.
	err := fs.WalkDir(templates, "templates", func(p string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		src, err := templates.ReadFile(p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, "templates/")
		rel = strings.ReplaceAll(rel, "__name__", d.Name)
		mode := os.FileMode(0o644)
		if strings.HasSuffix(rel, ".sh.tmpl") {
			mode = 0o755
		}
		if !strings.HasSuffix(rel, ".tmpl") {
			files = append(files, File{Path: rel, Content: src, Mode: mode})
			return nil
		}
		rel = strings.TrimSuffix(rel, ".tmpl")
		t, err := template.New(rel).Delims("[[", "]]").Funcs(funcs).Option("missingkey=error").Parse(string(src))
		if err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, d); err != nil {
			return fmt.Errorf("template %s: %w", p, err)
		}
		if strings.TrimSpace(buf.String()) == "" {
			return nil // a template may opt out, e.g. A2A config without agents
		}
		files = append(files, File{Path: rel, Content: buf.Bytes(), Mode: mode})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Data plane config, rendered by the same code the control plane uses.
	adapter, err := dataplane.New(e.Dataplane, dataplane.Options{
		BaseURL: "http://gateway:3000", A2AURL: "http://gateway:3100", OTLPEndpoint: "http://otel-collector:4317",
	})
	if err != nil {
		return nil, err
	}
	gw, err := adapter.Render(e, dataplane.State{})
	if err != nil {
		return nil, err
	}
	for _, f := range gw {
		files = append(files, File{Path: "gateway/" + f.Path, Content: f.Content, Mode: 0o644})
	}

	// Policy bundle and data, so auditors can `opa eval` exactly what runs.
	for name, b := range policy.Files() {
		files = append(files, File{Path: "policy/" + name, Content: b, Mode: 0o644})
	}
	pd, _ := json.MarshalIndent(map[string]any{"estate": policy.Data(e, nil)}, "", "  ")
	files = append(files, File{Path: "policy/data.json", Content: append(pd, '\n'), Mode: 0o644})

	files = append(files,
		File{Path: "estate.json", Content: e.JSON(), Mode: 0o644},
		File{Path: "CONTROLS.md", Content: controls.Markdown(controls.Build(e, nil)), Mode: 0o644},
	)
	if len(opts.CDL) > 0 {
		files = append(files, File{Path: "estate.cdl", Content: opts.CDL, Mode: 0o644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// ManifestPath is where Write records what it generated.
const ManifestPath = ".chautari/manifest.json"

// Manifest records the hash of every generated file.
type Manifest struct {
	Generator string            `json:"generator"`
	Estate    string            `json:"estate_digest"`
	Files     map[string]string `json:"files"`
}

// Report lists what Write did.
type Report struct {
	Created, Updated, Unchanged, Skipped, Removed []string
}

// Changed reports whether Write modified anything on disk.
func (r Report) Changed() bool {
	return len(r.Created)+len(r.Updated)+len(r.Removed) > 0
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Write materialises files under dir.
//
//   - a file whose content already matches is left untouched (not even its mtime);
//   - a file that differs from what we generated last time was edited by a
//     human: it is skipped (and reported) unless force is set;
//   - a file we generated last time that is no longer generated is removed,
//     unless it was edited.
func Write(dir string, files []File, estateDigest, version string, force bool) (Report, error) {
	var rep Report
	old := Manifest{Files: map[string]string{}}
	if b, err := os.ReadFile(filepath.Join(dir, ManifestPath)); err == nil {
		if err := json.Unmarshal(b, &old); err != nil {
			return rep, fmt.Errorf("corrupt %s: %w", ManifestPath, err)
		}
	}
	for path := range old.Files {
		if !filepath.IsLocal(filepath.FromSlash(path)) {
			return rep, fmt.Errorf("%s lists %q, which is outside the output directory; refusing to touch it", ManifestPath, path)
		}
	}
	next := Manifest{Generator: "chautari " + version, Estate: estateDigest, Files: map[string]string{}}
	for _, f := range files {
		if !filepath.IsLocal(filepath.FromSlash(f.Path)) {
			return rep, fmt.Errorf("generated path %q escapes the output directory", f.Path)
		}
		p := filepath.Join(dir, filepath.FromSlash(f.Path))
		want := hash(f.Content)
		cur, err := os.ReadFile(p)
		switch {
		case err == nil && hash(cur) == want:
			rep.Unchanged = append(rep.Unchanged, f.Path)
			next.Files[f.Path] = want
			continue
		case err == nil && !force:
			prev, known := old.Files[f.Path]
			if !known || hash(cur) != prev {
				// Exists and isn't what we last wrote: a human owns it now.
				rep.Skipped = append(rep.Skipped, f.Path)
				if known {
					next.Files[f.Path] = prev
				}
				continue
			}
			rep.Updated = append(rep.Updated, f.Path)
		case err == nil:
			rep.Updated = append(rep.Updated, f.Path)
		case os.IsNotExist(err):
			rep.Created = append(rep.Created, f.Path)
		default:
			return rep, err
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return rep, err
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(p, f.Content, mode); err != nil {
			return rep, err
		}
		next.Files[f.Path] = want
	}
	// Remove files we generated before but no longer generate.
	for path, h := range old.Files {
		if _, still := next.Files[path]; still {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(path))
		cur, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if hash(cur) != h && !force {
			rep.Skipped = append(rep.Skipped, path)
			continue
		}
		if err := os.Remove(p); err != nil {
			return rep, err
		}
		rep.Removed = append(rep.Removed, path)
	}
	mb, _ := json.MarshalIndent(next, "", "  ")
	mb = append(mb, '\n')
	mp := filepath.Join(dir, ManifestPath)
	if cur, err := os.ReadFile(mp); err != nil || !bytes.Equal(cur, mb) {
		if err := os.MkdirAll(filepath.Dir(mp), 0o755); err != nil {
			return rep, err
		}
		if err := os.WriteFile(mp, mb, 0o644); err != nil {
			return rep, err
		}
	}
	for _, l := range []*[]string{&rep.Created, &rep.Updated, &rep.Unchanged, &rep.Skipped, &rep.Removed} {
		sort.Strings(*l)
	}
	return rep, nil
}
