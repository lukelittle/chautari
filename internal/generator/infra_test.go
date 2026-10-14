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
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/estate"
)

// A second estate exercising the other branches: LiteLLM, Bedrock, an API-key
// provider, no tools and no agents.
const infraBedrockCDL = `
estate acme-ai {
  org "Acme Corp",
  dataplane litellm,
  region eu-west-1,
  environment prod
}
provider br { type bedrock, region eu-west-1 }
provider oa { type openai }
model titan { provider br, id "amazon.titan-text-express-v1", approved true, data-class internal }
model gpt { provider oa, id "gpt-4o", approved true, data-class internal }
team research { models [titan, gpt], clearance internal }
app notebook { team research }
`

var infraHelmFiles = []string{
	"Chart.yaml",
	"values.yaml",
	"README.md",
	".helmignore",
	"templates/_helpers.tpl",
	"templates/NOTES.txt",
	"templates/deployment.yaml",
	"templates/service.yaml",
	"templates/configmap.yaml",
	"templates/secret.yaml",
	"templates/serviceaccount.yaml",
	"templates/ingress.yaml",
	"templates/pdb.yaml",
	"templates/networkpolicy.yaml",
}

var infraTerraformFiles = []string{
	"versions.tf",
	"variables.tf",
	"main.tf",
	"ecs.tf",
	"rds.tf",
	"iam.tf",
	"alb.tf",
	"secrets.tf",
	"outputs.tf",
	"terraform.tfvars.example",
	"README.md",
}

type infraCase struct {
	name string
	e    *estate.Estate
	cdl  []byte
}

func infraCases(t *testing.T) []infraCase {
	t.Helper()
	const path = "../../examples/himalayan-bank.cdl"
	hb, err := cdl.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	acme, err := cdl.Compile("acme.cdl", infraBedrockCDL)
	if err != nil {
		t.Fatal(err)
	}
	return []infraCase{
		{name: "himalayan-bank", e: hb, cdl: src},
		{name: "acme-ai", e: acme, cdl: []byte(infraBedrockCDL)},
	}
}

func infraGenerate(t *testing.T, c infraCase) (Data, map[string]File, []File) {
	t.Helper()
	opts := Options{Version: "0.1.0", Demo: true, CDL: c.cdl}
	files, err := Generate(c.e, opts)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]File{}
	for _, f := range files {
		m[f.Path] = f
	}
	return NewData(c.e, opts), m, files
}

func isInfra(path string) bool {
	return strings.HasPrefix(path, "helm/") || strings.HasPrefix(path, "terraform/")
}

func TestInfraTemplates(t *testing.T) {
	for _, c := range infraCases(t) {
		t.Run(c.name, func(t *testing.T) {
			d, files, _ := infraGenerate(t, c)
			chart := "helm/" + d.Name + "/"
			if d.Name != c.name {
				t.Fatalf("dns name = %q, want %q", d.Name, c.name)
			}

			for _, f := range infraHelmFiles {
				if _, ok := files[chart+f]; !ok {
					t.Errorf("missing %s%s", chart, f)
				}
			}
			for _, f := range infraTerraformFiles {
				if _, ok := files["terraform/aws/"+f]; !ok {
					t.Errorf("missing terraform/aws/%s", f)
				}
			}

			// No template delimiters or .tmpl names leak into the output.
			for p, f := range files {
				if !isInfra(p) {
					continue
				}
				if strings.HasSuffix(p, ".tmpl") || strings.Contains(p, "__name__") {
					t.Errorf("unrendered path %s", p)
				}
				if bytes.Contains(f.Content, []byte("[[")) || bytes.Contains(f.Content, []byte("]]")) {
					t.Errorf("%s contains a [[ ]] template delimiter", p)
				}
				if bytes.Contains(f.Content, []byte("<no value>")) {
					t.Errorf("%s contains <no value>", p)
				}
			}

			// Chart.yaml
			var meta struct {
				APIVersion  string `yaml:"apiVersion"`
				Name        string `yaml:"name"`
				Version     string `yaml:"version"`
				AppVersion  string `yaml:"appVersion"`
				Description string `yaml:"description"`
			}
			if err := yaml.Unmarshal(files[chart+"Chart.yaml"].Content, &meta); err != nil {
				t.Fatalf("Chart.yaml: %v", err)
			}
			if meta.APIVersion != "v2" || meta.Name != d.Name || meta.AppVersion != "0.1.0" || meta.Version != "0.1.0" {
				t.Errorf("Chart.yaml = %+v", meta)
			}
			if !strings.Contains(meta.Description, c.e.Org) {
				t.Errorf("Chart.yaml description %q does not mention %q", meta.Description, c.e.Org)
			}

			// values.yaml
			var values struct {
				Dataplane    string            `yaml:"dataplane"`
				ReplicaCount int               `yaml:"replicaCount"`
				Estate       string            `yaml:"estate"`
				ProviderKeys map[string]string `yaml:"providerKeys"`
				Image        struct {
					Repository string `yaml:"repository"`
					Tag        string `yaml:"tag"`
				} `yaml:"image"`
				Gateway struct {
					Image struct {
						Repository string `yaml:"repository"`
					} `yaml:"image"`
					A2A bool `yaml:"a2a"`
				} `yaml:"gateway"`
				AWS struct {
					Region string `yaml:"region"`
				} `yaml:"aws"`
				PodSecurityContext struct {
					RunAsUser int `yaml:"runAsUser"`
				} `yaml:"podSecurityContext"`
				Service struct {
					Type string `yaml:"type"`
					Port int    `yaml:"port"`
				} `yaml:"service"`
			}
			if err := yaml.Unmarshal(files[chart+"values.yaml"].Content, &values); err != nil {
				t.Fatalf("values.yaml: %v", err)
			}
			if values.Image.Repository != "ghcr.io/lukelittle/chautari" || values.Image.Tag != "" {
				t.Errorf("image = %+v, want repository ghcr.io/lukelittle/chautari with tag from appVersion", values.Image)
			}
			if values.Gateway.Image.Repository != d.GatewayImage {
				t.Errorf("gateway image = %q, want %q", values.Gateway.Image.Repository, d.GatewayImage)
			}
			if values.Dataplane != d.Dataplane || values.Gateway.A2A != d.HasA2A {
				t.Errorf("dataplane/a2a = %q/%v, want %q/%v", values.Dataplane, values.Gateway.A2A, d.Dataplane, d.HasA2A)
			}
			if values.ReplicaCount != 2 || values.Estate != "" || values.PodSecurityContext.RunAsUser != 65532 {
				t.Errorf("values = %+v", values)
			}
			if values.Service.Type != "ClusterIP" || values.Service.Port != 8080 {
				t.Errorf("service = %+v", values.Service)
			}
			if d.UsesBedrock != (values.AWS.Region != "") {
				t.Errorf("aws.region = %q with UsesBedrock=%v", values.AWS.Region, d.UsesBedrock)
			}
			if len(d.ProviderEnvs) == 0 {
				t.Fatal("test estates should declare provider credentials")
			}
			for _, env := range d.ProviderEnvs {
				if _, ok := values.ProviderKeys[env]; !ok {
					t.Errorf("values.yaml providerKeys lacks %s", env)
				}
			}
			if len(values.ProviderKeys) != len(d.ProviderEnvs) {
				t.Errorf("providerKeys = %v, want %v", values.ProviderKeys, d.ProviderEnvs)
			}

			// Terraform: provider secrets and defaults.
			vars := string(files["terraform/aws/variables.tf"].Content)
			for _, env := range d.ProviderEnvs {
				if !strings.Contains(vars, `"`+env+`"`) {
					t.Errorf("variables.tf provider_key_names lacks %s", env)
				}
			}
			for _, want := range []string{`default     = "` + d.Name + `"`, `default     = "` + d.Image + `"`, `default     = "` + d.GatewayImage + `"`, `default     = "` + c.e.Region + `"`} {
				if !strings.Contains(vars, want) {
					t.Errorf("variables.tf lacks %s", want)
				}
			}
			if !strings.Contains(string(files["terraform/aws/secrets.tf"].Content), "for_each = toset(var.provider_key_names)") {
				t.Error("secrets.tf does not create a secret per provider credential")
			}

			// Bedrock permissions only when the estate uses Bedrock.
			for p, f := range files {
				if !isInfra(p) {
					continue
				}
				has := bytes.Contains(f.Content, []byte("bedrock:InvokeModel"))
				if has && !d.UsesBedrock {
					t.Errorf("%s grants Bedrock but the estate does not use it", p)
				}
			}
			iam := string(files["terraform/aws/iam.tf"].Content)
			for _, action := range []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream", "bedrock:ApplyGuardrail"} {
				if strings.Contains(iam, `"`+action+`"`) != d.UsesBedrock {
					t.Errorf("iam.tf %s present=%v, UsesBedrock=%v", action, !d.UsesBedrock, d.UsesBedrock)
				}
			}

			t.Run("helm", func(t *testing.T) { infraHelm(t, d, files) })
			t.Run("terraform", func(t *testing.T) { infraTerraform(t, files) })
		})
	}
}

func infraWrite(t *testing.T, files map[string]File) string {
	t.Helper()
	dir := t.TempDir()
	var list []File
	for _, f := range files {
		list = append(list, f)
	}
	if _, err := Write(dir, list, "test", "0.1.0", false); err != nil {
		t.Fatal(err)
	}
	return dir
}

func infraRun(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func infraHelm(t *testing.T, d Data, files map[string]File) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not on PATH")
	}
	root := infraWrite(t, files)
	chart := filepath.Join(root, "helm", d.Name)
	home := t.TempDir()
	env := []string{
		"HELM_CACHE_HOME=" + filepath.Join(home, "cache"),
		"HELM_CONFIG_HOME=" + filepath.Join(home, "config"),
		"HELM_DATA_HOME=" + filepath.Join(home, "data"),
	}
	set := []string{
		"--set-file", "estate=" + filepath.Join(root, "estate.cdl"),
		"--set", "database.url=postgres://chautari:pw@db:5432/chautari?sslmode=require",
	}

	if out, err := infraRun(t, root, env, helm, append([]string{"lint", "--strict", chart}, set...)...); err != nil {
		t.Fatalf("helm lint: %v\n%s", err, out)
	}
	// Missing mandatory values fail with a helpful message.
	if out, err := infraRun(t, root, env, helm, "template", "x", chart, "--kube-version", "1.30.0", "--set", "database.url=postgres://db/chautari"); err == nil || !strings.Contains(out, "--set-file estate=") {
		t.Errorf("helm template without estate should fail with guidance; err=%v\n%s", err, out)
	}

	variants := map[string][]string{
		"default": nil,
		"existing-secret": {"--set", "existingSecret=chautari-creds", "--set", "ingress.enabled=true",
			"--set", "ingress.className=nginx", "--set", "otel.endpoint=http://otel:4318",
			"--set", "policies.extra\\.rego=package chautari.extra"},
	}
	for name, extra := range variants {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"template", "rel", chart, "--namespace", "ns", "--kube-version", "1.30.0"}, set...)
			out, err := infraRun(t, root, env, helm, append(args, extra...)...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			kinds := infraCheckManifests(t, d, out, name == "existing-secret")
			want := []string{"ConfigMap", "Deployment", "NetworkPolicy", "PodDisruptionBudget", "Service", "ServiceAccount"}
			if name == "default" {
				want = append(want, "Secret")
			} else {
				want = append(want, "Ingress")
			}
			for _, k := range want {
				if kinds[k] == 0 {
					t.Errorf("no %s rendered", k)
				}
			}
			if name == "existing-secret" && kinds["Secret"] != 0 {
				t.Error("a Secret was rendered although existingSecret is set")
			}
		})
	}
}

// infraCheckManifests decodes `helm template` output and checks the topology:
// one Service on 8080, an init container rendering the gateway config, the
// gateway sidecar mounting /gateway read-only.
func infraCheckManifests(t *testing.T, d Data, out string, existing bool) map[string]int {
	t.Helper()
	kinds := map[string]int{}
	dec := yaml.NewDecoder(strings.NewReader(out))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decode helm output: %v", err)
		}
		if doc == nil {
			continue
		}
		kind, _ := doc["kind"].(string)
		kinds[kind]++
		switch kind {
		case "Service":
			ports := infraPath(doc, "spec", "ports").([]any)
			if len(ports) != 1 || ports[0].(map[string]any)["port"] != 8080 {
				t.Errorf("service ports = %v, want only 8080", ports)
			}
		case "Deployment":
			spec := infraPath(doc, "spec", "template", "spec").(map[string]any)
			inits := spec["initContainers"].([]any)
			init := inits[0].(map[string]any)
			args := strings.Join(infraStrings(init["args"]), " ")
			if !strings.Contains(args, "render-gateway") || !strings.Contains(args, "/gateway/"+d.GatewayConfigFile) {
				t.Errorf("init args = %q", args)
			}
			var names []string
			for _, c := range spec["containers"].([]any) {
				c := c.(map[string]any)
				names = append(names, c["name"].(string))
				switch c["name"] {
				case "chautari":
					if c["image"] != d.Image {
						t.Errorf("chautari image = %v, want %s", c["image"], d.Image)
					}
					if len(c["ports"].([]any)) != 1 {
						t.Errorf("chautari ports = %v", c["ports"])
					}
				case "gateway":
					if c["image"] != d.GatewayImage {
						t.Errorf("gateway image = %v, want %s", c["image"], d.GatewayImage)
					}
					if c["ports"] != nil {
						t.Errorf("gateway sidecar must not declare ports: %v", c["ports"])
					}
					var envs []string
					for _, e := range c["env"].([]any) {
						envs = append(envs, e.(map[string]any)["name"].(string))
					}
					for _, want := range d.ProviderEnvs {
						if !slices.Contains(envs, want) {
							t.Errorf("gateway env lacks %s", want)
						}
					}
					for _, m := range c["volumeMounts"].([]any) {
						m := m.(map[string]any)
						if m["mountPath"] == "/gateway" && m["readOnly"] != true {
							t.Error("gateway must mount /gateway read-only")
						}
					}
				}
			}
			if !slices.Equal(names, []string{"chautari", "gateway"}) {
				t.Errorf("containers = %v", names)
			}
			ann := infraPath(doc, "spec", "template", "metadata", "annotations").(map[string]any)
			if _, ok := ann["checksum/config"]; !ok {
				t.Error("pod template lacks checksum/config")
			}
			if existing {
				if !strings.Contains(out, "name: chautari-creds") {
					t.Error("existingSecret not referenced")
				}
			}
		}
	}
	return kinds
}

func infraPath(v any, keys ...string) any {
	for _, k := range keys {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	return v
}

func infraStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, s := range l {
		out = append(out, s.(string))
	}
	return out
}

func infraTerraform(t *testing.T, files map[string]File) {
	tf, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform not on PATH")
	}
	root := infraWrite(t, files)
	dir := filepath.Join(root, "terraform", "aws")
	env := []string{"TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"}

	if out, err := infraRun(t, dir, env, tf, "fmt", "-check", "-recursive", "-diff"); err != nil {
		t.Fatalf("terraform fmt: %v\n%s", err, out)
	}
	if out, err := infraRun(t, dir, env, tf, "init", "-backend=false", "-input=false", "-no-color"); err != nil {
		// Provider downloads need registry.terraform.io (or a mirror configured
		// through TF_CLI_CONFIG_FILE). Without network, validation can't run.
		for _, s := range []string{"Failed to query available provider packages", "Failed to install provider", "could not connect", "registry.terraform.io"} {
			if strings.Contains(out, s) {
				t.Skipf("terraform init could not fetch providers:\n%s", out)
			}
		}
		t.Fatalf("terraform init: %v\n%s", err, out)
	}
	if out, err := infraRun(t, dir, env, tf, "validate", "-no-color"); err != nil {
		t.Fatalf("terraform validate: %v\n%s", err, out)
	}
}
