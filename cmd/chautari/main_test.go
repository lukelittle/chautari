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

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAllowsFlagsAfterPositionals(t *testing.T) {
	for _, args := range [][]string{
		{"estate.cdl", "-o", "out", "--force"},
		{"-o", "out", "estate.cdl", "--force"},
		{"--force", "-o", "out", "estate.cdl"},
	} {
		fs := newFlagSet()
		out := fs.String("o", ".", "")
		force := fs.Bool("force", false, "")
		pos, err := parse(fs, args)
		if err != nil || len(pos) != 1 || pos[0] != "estate.cdl" || *out != "out" || !*force {
			t.Fatalf("%v → %v %q %v %v", args, pos, *out, *force, err)
		}
	}
}

func TestInitValidateGenerate(t *testing.T) {
	dir := t.TempDir()
	cdlPath := filepath.Join(dir, "estate.cdl")
	if err := runInit([]string{"--name", "acme", cdlPath}); err != nil {
		t.Fatal(err)
	}
	if err := runInit([]string{cdlPath}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("init must not overwrite: %v", err)
	}
	if err := runValidate([]string{cdlPath}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := runGenerate([]string{cdlPath, "-o", out, "-q"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"docker-compose.yml", "gateway/gateway.yaml", "helm/acme/Chart.yaml", "terraform/aws/main.tf", "CONTROLS.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	gw := filepath.Join(dir, "gw.yaml")
	if err := runRenderGateway([]string{"--estate", cdlPath, "--out", gw}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(gw)
	if !strings.Contains(string(b), "provider: bedrock") {
		t.Fatalf("render-gateway:\n%s", b)
	}
}

func TestRenderGatewayFromEnv(t *testing.T) {
	src, _ := os.ReadFile("../../examples/himalayan-bank.cdl")
	t.Setenv("CHAUTARI_ESTATE", "")
	t.Setenv("CHAUTARI_ESTATE_CDL", string(src))
	gw := filepath.Join(t.TempDir(), "gateway", "gateway.yaml")
	if err := runRenderGateway([]string{"--out", gw}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(gw); !strings.Contains(string(b), "claude-sonnet-4-5") {
		t.Fatal("estate from CHAUTARI_ESTATE_CDL was not rendered")
	}
}

func TestReportAndAuditVerifyErrors(t *testing.T) {
	if err := runReport([]string{"controls", "../../examples/himalayan-bank.cdl", "-o", filepath.Join(t.TempDir(), "c.md")}); err != nil {
		t.Fatal(err)
	}
	if err := runAudit([]string{"verify"}); err == nil {
		t.Fatal("verify without a file must error")
	}
}

func newFlagSet() *flag.FlagSet { return flag.NewFlagSet("test", flag.ContinueOnError) }
