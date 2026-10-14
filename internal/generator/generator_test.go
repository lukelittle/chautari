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

package generator

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/estate"
)

func example(t *testing.T) (*estate.Estate, []byte) {
	t.Helper()
	src, err := os.ReadFile("../../examples/himalayan-bank.cdl")
	if err != nil {
		t.Fatal(err)
	}
	e, err := cdl.Compile("himalayan-bank.cdl", string(src))
	if err != nil {
		t.Fatal(err)
	}
	return e, src
}

func generate(t *testing.T, e *estate.Estate, src []byte, demo bool) []File {
	t.Helper()
	files, err := Generate(e, Options{Version: "0.1.0", CDL: src, Demo: demo})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestGenerateProducesTheStack(t *testing.T) {
	e, src := example(t)
	files := generate(t, e, src, true)
	have := map[string][]byte{}
	for _, f := range files {
		have[f.Path] = f.Content
	}
	for _, want := range []string{
		"docker-compose.yml", ".env.example", "estate.cdl", "estate.json", "CONTROLS.md",
		"gateway/gateway.yaml", "otel/collector.yaml", "policy/authz.rego", "policy/data.json",
		"helm/himalayan-bank/Chart.yaml", "terraform/aws/main.tf",
	} {
		if _, ok := have[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	// Compose is valid YAML with the services we promise.
	var compose struct {
		Services map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal(have["docker-compose.yml"], &compose); err != nil {
		t.Fatalf("compose: %v", err)
	}
	for _, svc := range []string{"postgres", "otel-collector", "chautari", "gateway", "mock-llm", "traffic"} {
		if _, ok := compose.Services[svc]; !ok {
			t.Errorf("compose missing service %s", svc)
		}
	}
	if !bytes.Contains(have["docker-compose.yml"], []byte("cr.agentgateway.dev/agentgateway:v1.6.0")) {
		t.Error("compose must pin the agentgateway image")
	}
	// The data plane is never published to the host.
	if bytes.Contains(have["docker-compose.yml"], []byte(`"3000:3000"`)) {
		t.Error("gateway port must not be published")
	}
	var otel map[string]any
	if err := yaml.Unmarshal(have["otel/collector.yaml"], &otel); err != nil {
		t.Fatalf("otel: %v", err)
	}
	for p, b := range have {
		if bytes.Contains(b, []byte("[[")) && !strings.HasSuffix(p, ".rego") {
			t.Errorf("%s: unrendered template delimiter", p)
		}
	}
	if !bytes.Equal(have["estate.cdl"], src) {
		t.Error("estate.cdl must be a byte-for-byte copy of the source")
	}
}

func TestDemoFlag(t *testing.T) {
	e, src := example(t)
	for _, f := range generate(t, e, src, false) {
		if f.Path == "docker-compose.yml" && bytes.Contains(f.Content, []byte("mock-llm:")) {
			t.Fatal("non-demo compose must not include the mock provider")
		}
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	e, src := example(t)
	a, b := generate(t, e, src, true), generate(t, e, src, true)
	if len(a) != len(b) {
		t.Fatal("file count differs")
	}
	for i := range a {
		if a[i].Path != b[i].Path || !bytes.Equal(a[i].Content, b[i].Content) {
			t.Fatalf("%s differs between runs", a[i].Path)
		}
	}
}

func TestWriteIsIdempotent(t *testing.T) {
	e, src := example(t)
	dir := t.TempDir()
	files := generate(t, e, src, true)

	rep, err := Write(dir, files, e.Digest(), "0.1.0", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != len(files) || rep.Changed() == false {
		t.Fatalf("first run: %+v", rep)
	}
	compose := filepath.Join(dir, "docker-compose.yml")
	before, _ := os.Stat(compose)
	time.Sleep(10 * time.Millisecond)

	rep, err = Write(dir, files, e.Digest(), "0.1.0", false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Changed() || len(rep.Unchanged) != len(files) || len(rep.Skipped) != 0 {
		t.Fatalf("second run must change nothing: %+v", rep)
	}
	after, _ := os.Stat(compose)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("unchanged files must not be rewritten")
	}
}

func TestWriteRespectsHumanEdits(t *testing.T) {
	e, src := example(t)
	dir := t.TempDir()
	files := generate(t, e, src, true)
	if _, err := Write(dir, files, e.Digest(), "0.1.0", false); err != nil {
		t.Fatal(err)
	}
	compose := filepath.Join(dir, "docker-compose.yml")
	edited := []byte("# my tweaks\n")
	os.WriteFile(compose, edited, 0o644)

	// The estate changes (a new team), so docker-compose would change too.
	e2, err := cdl.Compile("himalayan-bank.cdl", string(src)+"\nteam treasury { models [gpt-4o] }\n")
	if err != nil {
		t.Fatal(err)
	}
	files2 := generate(t, e2, src, true)
	rep, err := Write(dir, files2, e2.Digest(), "0.1.0", false)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(rep.Skipped, "docker-compose.yml") {
		t.Fatalf("edited file must be skipped: %+v", rep)
	}
	if got, _ := os.ReadFile(compose); !bytes.Equal(got, edited) {
		t.Fatal("edited file was overwritten")
	}
	if !contains(rep.Updated, "estate.json") {
		t.Fatalf("unedited files must update: %+v", rep)
	}
	// Still skipped on the next run: the manifest remembers what we wrote.
	rep, _ = Write(dir, files2, e2.Digest(), "0.1.0", false)
	if !contains(rep.Skipped, "docker-compose.yml") || rep.Changed() {
		t.Fatalf("third run: %+v", rep)
	}
	// --force takes it back.
	rep, _ = Write(dir, files2, e2.Digest(), "0.1.0", true)
	if !contains(rep.Updated, "docker-compose.yml") {
		t.Fatalf("force: %+v", rep)
	}
}

func TestWriteRemovesFilesNoLongerGenerated(t *testing.T) {
	e, src := example(t)
	dir := t.TempDir()
	files := generate(t, e, src, true)
	Write(dir, files, e.Digest(), "0.1.0", false)
	// Pretend estate.cdl is no longer generated.
	var fewer []File
	for _, f := range files {
		if f.Path != "estate.cdl" {
			fewer = append(fewer, f)
		}
	}
	rep, err := Write(dir, fewer, e.Digest(), "0.1.0", false)
	if err != nil || !contains(rep.Removed, "estate.cdl") {
		t.Fatalf("%+v %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "estate.cdl")); !os.IsNotExist(err) {
		t.Fatal("stale generated file still on disk")
	}
}

func TestDNSName(t *testing.T) {
	for in, want := range map[string]string{"Himalayan Bank": "himalayan-bank", "a__b": "a-b", "": "chautari", "--x--": "x"} {
		if got := DNSName(in); got != want {
			t.Errorf("DNSName(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestManifestCannotEscapeOutputDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "out")
	os.MkdirAll(filepath.Join(dir, ".chautari"), 0o755)
	victim := filepath.Join(root, "victim.txt")
	os.WriteFile(victim, []byte("keep me"), 0o644)
	sum := hash([]byte("keep me"))
	os.WriteFile(filepath.Join(dir, ManifestPath), []byte(`{"files":{"../victim.txt":"`+sum+`"}}`), 0o644)
	e, src := example(t)
	if _, err := Write(dir, generate(t, e, src, false), e.Digest(), "0.1.0", true); err == nil {
		t.Fatal("a manifest pointing outside the output directory must be refused")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("file outside the output directory was deleted")
	}
	if _, err := Write(dir, []File{{Path: "../escape.txt", Content: []byte("x")}}, "", "0.1.0", false); err == nil {
		t.Fatal("generated paths must stay inside the output directory")
	}
}

func TestVertexProjectIsPassedToTheGateway(t *testing.T) {
	e, err := cdl.Compile("v.cdl", `provider gcp { type vertex, region europe-west4 }
model g { provider gcp, approved true }
team t { models [g] }`)
	if err != nil {
		t.Fatal(err)
	}
	files, err := Generate(e, Options{Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if (f.Path == "docker-compose.yml" || f.Path == ".env.example") && !bytes.Contains(f.Content, []byte("GOOGLE_CLOUD_PROJECT")) {
			t.Errorf("%s does not pass GOOGLE_CLOUD_PROJECT to the gateway", f.Path)
		}
	}
}
