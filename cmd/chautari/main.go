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

// Command chautari describes, generates and governs an AI estate.
//
//	chautari init                       write a starter estate.cdl
//	chautari validate estate.cdl        check a CDL file
//	chautari generate estate.cdl -o out render the whole stack (idempotent)
//	chautari serve                      run the control plane
//	chautari report controls ...        controls-mapping report
//	chautari audit verify export.jsonl  verify an audit export offline
//	chautari demo traffic ...           drive demo traffic
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lukelittle/chautari/internal/audit"
	"github.com/lukelittle/chautari/internal/cdl"
	"github.com/lukelittle/chautari/internal/controls"
	"github.com/lukelittle/chautari/internal/dataplane"
	"github.com/lukelittle/chautari/internal/demo"
	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/generator"
	"github.com/lukelittle/chautari/internal/guardrails"
	"github.com/lukelittle/chautari/internal/server"
	"github.com/lukelittle/chautari/internal/store"
	"github.com/lukelittle/chautari/internal/telemetry"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const banner = `
      ,     chautari %s
   .-'|'-.  the open AI control plane
  /  \|/  \  a resting place on the trail, owned by no one
  '-._|_.-'
  ____|____
`

func usage() {
	fmt.Fprintf(os.Stderr, banner, version)
	fmt.Fprint(os.Stderr, `
Usage:
  chautari init [estate.cdl]                       write a starter estate
  chautari validate <estate.cdl>                   check a CDL file and summarise it
  chautari generate <estate.cdl> [-o dir] [flags]  generate the stack (idempotent)
  chautari serve [flags]                           run the control plane
  chautari render-gateway --out <file> [--estate f] render data plane config from CDL
  chautari report controls <estate.cdl> [flags]    AI controls-mapping report
  chautari audit verify <export.jsonl>             verify an audit export offline
  chautari audit export --server URL -o file       download an audit export
  chautari demo traffic --server URL               send demo traffic
  chautari healthcheck [--url URL]                 container health probe
  chautari version

Run 'chautari <command> -h' for flags.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = runInit(args)
	case "validate":
		err = runValidate(args)
	case "generate", "gen":
		err = runGenerate(args)
	case "serve":
		err = runServe(args)
	case "render-gateway":
		err = runRenderGateway(args)
	case "report":
		err = runReport(args)
	case "audit":
		err = runAudit(args)
	case "demo":
		err = runDemo(args)
	case "healthcheck":
		err = runHealthcheck(args)
	case "version", "--version", "-v":
		fmt.Println("chautari", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "chautari: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "chautari:", err)
		os.Exit(1)
	}
}

// env returns the environment value or a default.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parse parses flags allowing positional arguments before or after them.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// loadEstate reads CDL from a path, or from CHAUTARI_ESTATE_CDL (the text
// itself) when no path is given.
func loadEstate(path string) (*estate.Estate, []byte, error) {
	if path == "" {
		if src := os.Getenv("CHAUTARI_ESTATE_CDL"); src != "" {
			e, err := cdl.Compile("estate.cdl", src)
			return e, []byte(src), err
		}
		return nil, nil, errors.New("no estate: pass --estate <file.cdl>, or set CHAUTARI_ESTATE or CHAUTARI_ESTATE_CDL")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	e, err := cdl.Compile(filepath.Base(path), string(b))
	return e, b, err
}

// ── init ───────────────────────────────────────────────────────────────────

const starter = `// %[1]s: your AI estate. Edit, then run: chautari generate %[2]s
estate %[1]s { org "%[1]s", dataplane agentgateway, region us-east-1 }

provider bedrock { type bedrock, region us-east-1 }

model claude-sonnet {
  provider bedrock, id "anthropic.claude-sonnet-4-5-20250929-v1:0",
  approved true, data-class internal, cost-in 3 usd/mtok, cost-out 15 usd/mtok
}

policy pii { redact inbound, block outbound ssn, card }
policy prompt-injection { block inbound injection }

team platform { models [claude-sonnet], budget 500 usd/month, rate 50k tokens/min }

app first-app { team platform, budget 50 usd/month }
`

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	name := fs.String("name", "", "estate name (default: current directory name)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	path := "estate.cdl"
	if len(pos) > 0 {
		path = pos[0]
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; not overwriting", path)
	}
	if *name == "" {
		wd, _ := os.Getwd()
		*name = generator.DNSName(filepath.Base(wd))
	}
	src := fmt.Sprintf(starter, *name, path)
	if _, err := cdl.Compile(path, src); err != nil {
		return fmt.Errorf("starter estate does not compile (bug): %w", err)
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Next: chautari generate %s -o .\n", path, path)
	return nil
}

// ── validate ───────────────────────────────────────────────────────────────

func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the compiled estate as JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: chautari validate <estate.cdl>")
	}
	e, _, err := loadEstate(pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		os.Stdout.Write(e.JSON())
		return nil
	}
	approved := 0
	for _, m := range e.Models {
		if m.Approved {
			approved++
		}
	}
	fmt.Printf("✓ %s is valid\n\n  estate     %s (%s)\n  dataplane  %s\n  providers  %d\n  models     %d (%d approved)\n  tools      %d\n  agents     %d\n  teams      %d\n  apps       %d\n  policies   %d\n  sha256     %s\n",
		pos[0], e.Name, e.Org, e.Dataplane, len(e.Providers), len(e.Models), approved, len(e.Tools), len(e.Agents),
		len(e.Teams), len(e.Apps), len(e.Policies), e.Source.SHA256)
	return nil
}

// ── generate ───────────────────────────────────────────────────────────────

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	out := fs.String("o", ".", "output directory")
	force := fs.Bool("force", false, "overwrite files you have edited")
	demoFlag := fs.Bool("demo", false, "include the offline mock provider and demo traffic in Compose")
	image := fs.String("image", "", "Chautari container image (default ghcr.io/lukelittle/chautari:<version>)")
	quiet := fs.Bool("q", false, "only print a summary")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: chautari generate <estate.cdl> [-o dir] [--demo] [--force]")
	}
	e, src, err := loadEstate(pos[0])
	if err != nil {
		return err
	}
	files, err := generator.Generate(e, generator.Options{Version: version, Image: *image, CDL: src, Demo: *demoFlag})
	if err != nil {
		return err
	}
	rep, err := generator.Write(*out, files, e.Digest(), version, *force)
	if err != nil {
		return err
	}
	if !*quiet {
		for _, p := range rep.Created {
			fmt.Printf("  create  %s\n", p)
		}
		for _, p := range rep.Updated {
			fmt.Printf("  update  %s\n", p)
		}
		for _, p := range rep.Removed {
			fmt.Printf("  remove  %s\n", p)
		}
		for _, p := range rep.Skipped {
			fmt.Printf("  skip    %s (edited by you; --force to overwrite)\n", p)
		}
	}
	fmt.Printf("\n%s: %d created, %d updated, %d unchanged, %d removed, %d skipped\n",
		*out, len(rep.Created), len(rep.Updated), len(rep.Unchanged), len(rep.Removed), len(rep.Skipped))
	if !rep.Changed() && len(rep.Skipped) == 0 {
		fmt.Println("Nothing to do. The trail is where you left it.")
	} else if len(rep.Created) > 0 {
		fmt.Printf("\nNext:\n  cd %s && cp .env.example .env   # set the secrets\n  docker compose up\n", *out)
	}
	return nil
}

// ── serve ──────────────────────────────────────────────────────────────────

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	estatePath := fs.String("estate", env("CHAUTARI_ESTATE", ""), "estate CDL file (env CHAUTARI_ESTATE; or CHAUTARI_ESTATE_CDL with the text)")
	addr := fs.String("addr", env("CHAUTARI_ADDR", ":8080"), "listen address")
	dbURL := fs.String("database-url", env("CHAUTARI_DATABASE_URL", ""), "Postgres URL; empty uses an in-memory store (dev only)")
	adminToken := fs.String("admin-token", env("CHAUTARI_ADMIN_TOKEN", ""), "shared admin token (people name themselves; separation of duties is advisory)")
	adminTokens := fs.String("admin-tokens", env("CHAUTARI_ADMIN_TOKENS", ""), "per-person admin tokens, name=token[,name=token] (identity comes from the token)")
	digestKey := fs.String("digest-key", env("CHAUTARI_DIGEST_KEY", ""), "key for prompt HMACs in the audit log (default: derived from the admin token)")
	dpName := fs.String("dataplane", env("CHAUTARI_DATAPLANE", ""), "agentgateway | litellm | direct (default: the estate's)")
	gwURL := fs.String("gateway-url", env("CHAUTARI_GATEWAY_URL", "http://127.0.0.1:3000"), "data plane LLM/MCP base URL")
	gwA2A := fs.String("gateway-a2a-url", env("CHAUTARI_GATEWAY_A2A_URL", ""), "data plane A2A base URL")
	gwKey := fs.String("gateway-key", env(dataplane.GatewayKeyEnv, ""), "internal key the data plane accepts")
	gwConfig := fs.String("gateway-config", env("CHAUTARI_GATEWAY_CONFIG", ""), "write the live data plane config here")
	policyDir := fs.String("policy-dir", env("CHAUTARI_POLICY_DIR", ""), "directory of extra .rego files (package chautari.custom)")
	logLevel := fs.String("log-level", env("CHAUTARI_LOG_LEVEL", "info"), "debug | info | warn | error")
	if _, err := parse(fs, args); err != nil {
		return err
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	e, _, err := loadEstate(*estatePath)
	if err != nil {
		return err
	}
	people, err := server.ParseAdminTokens(*adminTokens)
	if err != nil {
		return err
	}
	if *adminToken == "" && len(people) == 0 {
		return errors.New("set CHAUTARI_ADMIN_TOKENS (per-person, recommended) or CHAUTARI_ADMIN_TOKEN")
	}
	if *digestKey == "" && len(people) > 0 && *adminToken == "" {
		return errors.New("with per-person admin tokens, set CHAUTARI_DIGEST_KEY so prompt digests survive token rotation")
	}
	if *gwKey == "" && *dpName != "direct" {
		return errors.New("set " + dataplane.GatewayKeyEnv + " (or --gateway-key): the data plane only trusts the checkpoint through it")
	}

	shutdownTracing, err := telemetry.Setup(ctx, env("OTEL_SERVICE_NAME", "chautari"), version)
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer shutdownTracing(context.Background()) //nolint:errcheck

	var st store.Store
	if *dbURL == "" {
		log.Warn("no CHAUTARI_DATABASE_URL: using the in-memory store; everything is lost on restart")
		st = store.NewMemory()
	} else {
		pg, err := store.OpenPostgres(ctx, *dbURL, 60*time.Second)
		if err != nil {
			return err
		}
		defer pg.Close()
		st = pg
	}

	name := e.Dataplane
	if *dpName != "" {
		name = *dpName
	}
	mcpURL := ""
	if name == "agentgateway" && *gwA2A == "" {
		// The gateway serves A2A on its own port; agents approved at runtime
		// must be reachable without redeploying with a new flag.
		if u, err := url.Parse(*gwURL); err == nil && u.Hostname() != "" {
			*gwA2A = u.Scheme + "://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(dataplane.AgentGatewayA2APort))
		}
	}
	if name == "direct" {
		// Direct talks to an OpenAI-compatible base URL (…/v1); its MCP and
		// A2A endpoints are assumed to live on the same host.
		base := strings.TrimSuffix(strings.TrimSuffix(*gwURL, "/"), "/v1")
		mcpURL = base + "/mcp"
		if *gwA2A == "" {
			*gwA2A = base
		}
	}
	adapter, err := dataplane.New(name, dataplane.Options{
		BaseURL: *gwURL, A2AURL: *gwA2A, MCPURL: mcpURL, InternalKey: *gwKey,
		OTLPEndpoint: otlpGRPC(), Transport: telemetry.Transport(nil),
	})
	if err != nil {
		return err
	}

	var bedrock guardrails.BedrockClient
	for _, p := range e.Policies {
		if p.BedrockGuardrail != "" {
			b, err := guardrails.NewBedrock(ctx, env("AWS_REGION", e.Region))
			if err != nil {
				return err
			}
			bedrock = b
			break
		}
	}

	srv, err := server.New(ctx, server.Config{
		Estate: e, Store: st, Adapter: adapter, AdminToken: *adminToken, AdminTokens: people, DigestKey: *digestKey,
		GatewayConfigPath: *gwConfig,
		PolicyDir:         *policyDir, Bedrock: bedrock, Logger: log, Version: version, UI: uiHandler(),
	})
	if err != nil {
		return err
	}
	go srv.Run(ctx)

	hs := &http.Server{
		Addr:              *addr,
		Handler:           telemetry.Handler(srv.Handler(), "chautari"),
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds how long a client may take to send its request; responses
		// stream, so there is deliberately no WriteTimeout.
		ReadTimeout:    2 * time.Minute,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("chautari is listening", "addr", *addr, "estate", e.Name, "dataplane", adapter.Name(), "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

// otlpGRPC derives the collector's gRPC endpoint (port 4317) for the data
// plane from the control plane's OTLP/HTTP endpoint (port 4318).
func otlpGRPC() string {
	if v := os.Getenv("CHAUTARI_DATAPLANE_OTLP_ENDPOINT"); v != "" {
		return v
	}
	v := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if v == "" {
		return ""
	}
	return strings.Replace(v, ":4318", ":4317", 1)
}

// ── render-gateway ─────────────────────────────────────────────────────────

func runRenderGateway(args []string) error {
	fs := flag.NewFlagSet("render-gateway", flag.ExitOnError)
	estatePath := fs.String("estate", env("CHAUTARI_ESTATE", ""), "estate CDL file (or CHAUTARI_ESTATE_CDL)")
	out := fs.String("out", "", "file to write (default stdout)")
	dpName := fs.String("dataplane", env("CHAUTARI_DATAPLANE", ""), "agentgateway | litellm")
	owner := fs.String("owner", "", "uid:gid to own the output file and its directory (for init containers running as root)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	e, _, err := loadEstate(*estatePath)
	if err != nil {
		return err
	}
	name := e.Dataplane
	if *dpName != "" {
		name = *dpName
	}
	adapter, err := dataplane.New(name, dataplane.Options{OTLPEndpoint: otlpGRPC()})
	if err != nil {
		return err
	}
	files, err := adapter.Render(e, dataplane.State{})
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("the %s data plane has no config to render", name)
	}
	if *out == "" {
		_, err = os.Stdout.Write(files[0].Content)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, files[0].Content, 0o644); err != nil {
		return err
	}
	if *owner == "" {
		return nil
	}
	uid, gid, ok := strings.Cut(*owner, ":")
	u, err1 := strconv.Atoi(uid)
	g, err2 := strconv.Atoi(gid)
	if !ok || err1 != nil || err2 != nil {
		return fmt.Errorf("--owner must be uid:gid, got %q", *owner)
	}
	for _, p := range []string{filepath.Dir(*out), *out} {
		if err := os.Chown(p, u, g); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	return nil
}

// ── report ─────────────────────────────────────────────────────────────────

func runReport(args []string) error {
	if len(args) == 0 || args[0] != "controls" {
		return errors.New("usage: chautari report controls <estate.cdl> [--format md|html|json] [-o file] [--server URL]")
	}
	fs := flag.NewFlagSet("report controls", flag.ExitOnError)
	format := fs.String("format", "md", "md | html | json")
	out := fs.String("o", "", "output file (default stdout)")
	serverURL := fs.String("server", "", "fetch a live report (with evidence) from a running control plane")
	token := fs.String("token", env("CHAUTARI_ADMIN_TOKEN", ""), "admin token for --server")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if *serverURL != "" {
		body, err := adminGET(*serverURL, *token, "/api/reports/controls?format="+*format)
		if err != nil {
			return err
		}
		defer body.Close()
		_, err = io.Copy(w, body)
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: chautari report controls <estate.cdl>, or --server URL for a live report")
	}
	e, _, err := loadEstate(pos[0])
	if err != nil {
		return err
	}
	rep := controls.Build(e, nil)
	switch *format {
	case "md", "markdown":
		_, err = w.Write(controls.Markdown(rep))
	case "html":
		var b []byte
		if b, err = controls.HTML(rep); err == nil {
			_, err = w.Write(b)
		}
	case "json":
		_, err = w.Write(mustJSON(rep))
	default:
		err = fmt.Errorf("unknown format %q", *format)
	}
	return err
}

// ── audit ──────────────────────────────────────────────────────────────────

func runAudit(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: chautari audit verify <export.jsonl> | chautari audit export --server URL -o file")
	}
	switch args[0] {
	case "verify":
		if len(args) != 2 {
			return errors.New("usage: chautari audit verify <export.jsonl>")
		}
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		res, err := audit.VerifyJSONL(f)
		if err != nil {
			return err
		}
		if !res.OK {
			fmt.Printf("✗ chain BROKEN at seq %d: %s\n  verified %d records before the break (seq %d to %d)\n",
				res.BrokenAt, res.Problem, res.Records, res.FirstSeq, res.LastSeq)
			os.Exit(1)
		}
		fmt.Printf("✓ chain verified: %d records, seq %d to %d\n  head %s\n", res.Records, res.FirstSeq, res.LastSeq, res.HeadHash)
		if res.FirstSeq != 1 {
			fmt.Println("  note: this export starts mid-chain; it is internally consistent. Compare its first prev_hash with the previous export's head.")
		}
		return nil
	case "export":
		fs := flag.NewFlagSet("audit export", flag.ExitOnError)
		serverURL := fs.String("server", "http://localhost:8080", "control plane URL")
		token := fs.String("token", env("CHAUTARI_ADMIN_TOKEN", ""), "admin token")
		out := fs.String("o", "audit.jsonl", "output file")
		format := fs.String("format", "jsonl", "jsonl | csv")
		from := fs.String("from", "", "start (RFC 3339 or YYYY-MM-DD)")
		to := fs.String("to", "", "end, exclusive")
		if _, err := parse(fs, args[1:]); err != nil {
			return err
		}
		q := "/api/audit/export?format=" + *format
		if *from != "" {
			q += "&from=" + *from
		}
		if *to != "" {
			q += "&to=" + *to
		}
		body, err := adminGET(*serverURL, *token, q)
		if err != nil {
			return err
		}
		defer body.Close()
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		n, err := io.Copy(f, body)
		if err == nil {
			fmt.Printf("wrote %s (%d bytes). Verify with: chautari audit verify %s\n", *out, n, *out)
		}
		return err
	}
	return fmt.Errorf("unknown audit command %q", args[0])
}

func adminGET(base, token, path string) (io.ReadCloser, error) {
	if token == "" {
		return nil, errors.New("set CHAUTARI_ADMIN_TOKEN or --token")
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(base, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return resp.Body, nil
}

// ── demo ───────────────────────────────────────────────────────────────────

func runDemo(args []string) error {
	if len(args) == 0 || args[0] != "traffic" {
		return errors.New("usage: chautari demo traffic --server URL [--rate N] [--duration 5m]")
	}
	fs := flag.NewFlagSet("demo traffic", flag.ExitOnError)
	serverURL := fs.String("server", "http://localhost:8080", "control plane URL")
	token := fs.String("token", env("CHAUTARI_ADMIN_TOKEN", ""), "admin token (to mint keys)")
	rate := fs.Float64("rate", 2, "requests per second")
	dur := fs.Duration("duration", 0, "stop after this long (0 = run until interrupted)")
	if _, err := parse(fs, args[1:]); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	return demo.Run(ctx, demo.Options{Server: *serverURL, AdminToken: *token, Rate: *rate, Duration: *dur, Logger: log})
}

// ── healthcheck ────────────────────────────────────────────────────────────

func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	u := fs.String("url", "http://127.0.0.1:8080/healthz", "URL to probe")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(*u)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}
