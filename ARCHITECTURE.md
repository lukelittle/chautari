# Chautari Architecture

> One binary to describe your AI estate, generate the stack that runs it, and
> govern every request that crosses it. Built on open infrastructure, owned by
> no one.

This document is the contract. If the code disagrees with it, one of them is a
bug.

---

## 1. Principles

1. **Don't rebuild what's already open.** Traffic is carried by
   [agentgateway](https://agentgateway.dev) (Linux Foundation, Apache 2.0).
   Policy is evaluated by [OPA](https://www.openpolicyagent.org) (CNCF,
   Apache 2.0). Telemetry is [OpenTelemetry](https://opentelemetry.io).
   Chautari is the control plane and the generator, nothing more.
2. **The estate is code.** An organisation's AI estate (providers, models, MCP
   tools, agents, teams, apps, policies, budgets) is declared in a `.cdl` file,
   reviewed in a pull request, and compiled. The running system is a projection
   of that file plus the approvals recorded since.
3. **Fail closed.** No policy decision means deny. An unknown model means deny.
   A guardrail that errors means deny. A broken audit chain is surfaced loudly.
4. **Evidence, not assertions.** Every request, policy decision, guardrail hit,
   approval, and key issuance lands in an append-only, hash-chained audit log.
   The controls report quotes that log; it never claims something the system
   cannot show.
5. **Boring underneath.** Postgres, a single static Go binary, plain YAML,
   deterministic generation. The whole test suite runs offline against a mock
   provider.

---

## 2. The picture

```
              ┌─────────────────────────── estate.cdl ───────────────────────────┐
              │  providers · models · tools · agents · teams · apps · policies  │
              └──────────────────────────────┬───────────────────────────────────┘
                                             │  chautari generate (idempotent)
              ┌──────────────────────────────▼───────────────────────────────────┐
              │ gateway config · compose · Helm · Terraform(AWS) · OTel · Rego   │
              │ data · controls report                                           │
              └──────────────────────────────────────────────────────────────────┘

  apps / agents                       CHAUTARI CONTROL PLANE (Go)
  ─────────────                ┌──────────────────────────────────────────────┐
  Authorization:               │  Checkpoint (/v1)          Admin API (/api)   │
  Bearer ck_…  ───────────────▶│   1 authenticate key       registry +         │
                               │   2 OPA decision            approvals          │
                               │   3 budget + rate check    keys, budgets      │
                               │   4 inbound guardrails     audit export       │
                               │   5 forward ──────────┐    controls report    │
                               │   8 outbound guardrails│   Admin UI (/)       │
                               │   9 meter + audit      │                       │
                               │                        │   Gateway renderer ───┼──▶ /config/gateway.yaml
                               └────────────────────────┼──────────┬───────────┘        (hot reload)
                                                        │          │
                                 internal key           ▼          ▼ Postgres (registry, keys,
                               ┌──────────────────────────────┐      spend, append-only audit)
                               │  DATA PLANE  (adapter)       │
                               │  agentgateway  │  LiteLLM    │
                               │  LLM · MCP · A2A             │──▶ OTel Collector
                               └──────┬───────────┬───────────┘
                                      ▼           ▼
                           Bedrock / OpenAI /   MCP servers,
                           Anthropic / mock     A2A agents
```

## 3. Components

| Package | Responsibility |
|---|---|
| `internal/cdl` | Lexer, parser, semantic validator for the Chautari Definition Language. Produces an `Estate`. |
| `internal/estate` | The compiled, validated, deterministic in-memory model every other package consumes. |
| `internal/generator` | Renders an `Estate` into a deployable tree. Idempotent writer with a manifest. |
| `internal/dataplane` | `Adapter` interface plus `agentgateway` and `litellm` implementations: config rendering and request forwarding. |
| `internal/policy` | Embedded OPA engine and Rego bundle. Answers "may this subject use this model/tool at this data class?" |
| `internal/guardrails` | Pluggable `Filter` chain: PII, prompt injection, blocked topics, Bedrock Guardrails adapter. |
| `internal/budget` | Spend budgets (USD per day/week/month) and token/request rate limits per team, app and key. |
| `internal/audit` | Hash-chained append-only log, verification, JSONL/CSV export. |
| `internal/registry` | Model, tool and agent lifecycle state machine with separation-of-duties. |
| `internal/store` | Persistence interface with Postgres and in-memory implementations. |
| `internal/controls` | Controls-mapping catalogue (NIST AI RMF, SR 11-7) and the evidence-backed report. |
| `internal/server` | HTTP surface: checkpoint, admin API, admin UI. |
| `cmd/chautari` | The CLI: `generate`, `validate`, `serve`, `report`, `audit`, `demo`. |
| `cmd/mock-llm` | OpenAI-compatible mock provider so everything runs offline. |

## 4. Request lifecycle (the vertical slice)

`POST /v1/chat/completions` on the checkpoint, OpenAI wire format:

1. **Authenticate.** `Authorization: Bearer ck_…`. Keys are stored as SHA-256
   hashes; the key resolves to an app, which belongs to a team. Unknown or
   revoked key → `401`.
2. **Resolve.** The requested model name is looked up in the registry. It must
   exist. The request's data class is the highest of `X-Chautari-Data-Class`,
   the app's default and the estate default: a caller can declare its data
   more sensitive than usual, never less.
3. **Decide (OPA).** Input `{subject, action: "model.invoke", resource, data_class}`
   is evaluated against `data.chautari.authz`. The model must be `approved`,
   listed in the team's entitlements, cleared for the data class, and the team
   must hold clearance for it. Any `deny` rule from operator-supplied Rego also
   blocks. Deny → `403` with reasons.
4. **Budget and rate.** The request's estimated cost (prompt estimate plus
   `max_tokens`, or 1,024 completion tokens) is reserved against key, app and
   team budgets; token and request rate limits are checked against sliding
   windows. Exceeded → `429`, audited as decision `limit`.
5. **Inbound guardrails.** Policies that apply to the team run over every
   string the model will read: message content and text parts, earlier tool
   call arguments, tool results, and tool and function descriptions.
   `redact` rewrites, `block` rejects (`400`), `flag` records only.
6. **Forward.** The request goes to the data-plane adapter with the internal
   gateway key. agentgateway routes it to the provider (with provider
   credentials it alone holds), emits OTel traces, and translates formats.
7. **Response.** The upstream call is detached from the client's connection:
   if the client hangs up, the provider still bills us, so the checkpoint
   still reads the usage and meters it.
8. **Outbound guardrails.** Same filter chain over everything the model said:
   content, refusals and tool call arguments, buffered or streamed.
9. **Meter and audit.** Usage tokens × model price → spend for key, app, team,
   settling the reservation. One audit record captures the decision,
   guardrail findings (types and counts, never raw content), tokens, cost and
   latency. The prompt is recorded only as an HMAC of its redacted text
   (`CHAUTARI_DIGEST_KEY`), which matches an incident to a record without
   letting anyone brute-force short PII out of the log.
10. **Evidence before delivery.** A buffered response is released only after
   its audit record is written. If the audit log is unavailable the client
   gets `503`, not an answer nobody can account for. The same holds for tool
   calls, key issuance and registry changes, which are recorded before they
   take effect.

Streaming (`"stream": true`) is accepted. Without outbound guardrails the stream
is passed through and usage is read from the final chunk. When an outbound
guardrail applies, the stream is buffered, checked, then replayed, because a
guardrail that runs after the bytes have left is not a guardrail.

MCP (`/mcp`) and A2A (`/a2a/<agent>/…`) also enter through the checkpoint,
which authenticates the key, decides with OPA (`tool.call`, `agent.call`),
audits, and proxies to agentgateway. MCP messages are parsed strictly
(duplicate keys, keys differing only in case, and batches are refused) and
the checkpoint forwards the message it re-encoded from that parse, so the
data plane can never read a different message than the one that was
authorised. A2A paths with encoded slashes or dot segments are refused, so a
call authorised for one agent cannot walk to another. It proxies with the internal key and
`X-Chautari-Team`/`X-Chautari-App` headers. Those headers are trustworthy in
the data plane because nothing but the checkpoint holds the internal key.
agentgateway then enforces the same entitlements a second time: Chautari
renders `mcpAuthorization` CEL rules (`request.headers["x-chautari-team"] ==
"lending" && mcp.tool.target == "jira-mcp" && mcp.tool.name in [...]`) from
the estate and registry, and only approved tool servers and agents are
routable at all. `POST /v1/tools/authorize` exposes the decision (audited)
for frameworks that want to ask first, and for LiteLLM, which has no MCP
authorization of its own.

## 5. Data plane adapter

```go
type Adapter interface {
    Name() string
    Render(e *estate.Estate, rt RuntimeState) ([]File, error) // config files
    Forward(ctx context.Context, req *Request) (*http.Response, error)
}
```

* **agentgateway** (default). Renders `gateway.yaml` using the `gateways`,
  `llm`, `mcp` and `binds` sections of agentgateway's standalone config (pinned
  to v1.6.0; every rendered file is validated against the upstream JSON schema
  in tests). The control plane re-renders the file whenever a model or tool is
  approved or retired. agentgateway hot-reloads it. That is the control loop.
* **litellm**. Renders LiteLLM's `config.yaml` (`model_list`) and forwards to
  its OpenAI-compatible proxy. LiteLLM has no MCP-authorization equivalent, so
  tool enforcement falls back to `/v1/tools/authorize`.
* **direct**. Test and development only. Forwards straight to an
  OpenAI-compatible base URL with no gateway in between.

**Topology.** The gateway runs next to the control plane, sharing a volume
for its config: a sidecar in the same pod (Helm) or task (ECS), a sibling
container on a shared volume (Compose). An init step (`chautari
render-gateway`) writes a config from CDL alone so the gateway can start; the
control plane then rewrites it from live state. Every replica re-reads the
registry from Postgres every 15 seconds and re-renders on change, so an
approval made through one replica reaches all of them.

The checkpoint never holds provider credentials. The data plane is not exposed
outside the deployment network; the only key it accepts is the internal one the
checkpoint presents. The upshot is one way in, and it's governed.

## 6. Registry and approvals

States: `requested → reviewed → approved → retired`, plus `rejected` from
`requested` or `reviewed`. Transitions are recorded in the audit log with actor
and comment.

* **Separation of duties.** The reviewer and approver must differ from the
  requester (SR 11-7's "effective challenge"). The API enforces it.
* **Estate-as-code.** `approved true` in CDL seeds the entry as `approved`, with
  the audit actor `cdl:<file>@<sha256>`. The approval *is* the merged pull
  request; the hash proves which file did it.
* **Retirement is a kill switch.** Retiring a model removes it from the gateway
  config and every OPA decision immediately on the replica that handled it,
  and within one resync interval everywhere else (MANAGE 2.4).
* **API-requested models.** A model can be requested through the API with a
  spec naming an estate provider. Once approved it is routable, but no team
  may use it until the CDL entitles one: the registry governs what exists,
  the estate governs who may use it.

## 7. Policy (OPA)

The Rego bundle is embedded (`internal/policy/rego/`). Its data document is the
estate plus live registry state. Operators can add `.rego` files (`--policy-dir`)
that contribute `deny contains msg if { ... }` rules; any message is a deny.
The generator also writes the bundle and data to `policy/` so auditors can run
`opa eval` against exactly what production runs.

Data classes are ordered: `public < internal < confidential < restricted`.
A request at class *c* needs `model.data_class >= c` and `team.clearance >= c`.

## 8. Guardrails

```go
type Filter interface {
    Name() string
    Inspect(ctx context.Context, dir Direction, text string) (Result, error)
}
```

Built in: `pii` (SSN, payment card with Luhn check, email, phone, IBAN, AWS
access keys), `injection` (heuristic scorer over known jailbreak and
instruction-override patterns), `topics` (blocked-topic phrases). `bedrock`
calls Bedrock's `ApplyGuardrail` through a narrow client interface so it can be
faked in tests. Actions: `redact`, `block`, `flag`. A filter error fails closed.

## 9. Budgets and rate limits

* Spend: USD per `day`, `week` or `month` at team, app and key scope. Windows are
  calendar-aligned in UTC. Spend is persisted (`spend` table) so restarts don't
  reset budgets.
* Rate: tokens or requests per `min`/`hour` at team and app scope, enforced
  in-process with a sliding window (per replica; the Helm chart notes this).
* Admission reserves the request's estimated cost in every applicable budget
  window, so concurrent requests on a replica cannot jointly spend past a
  budget; the actual cost settles the reservation afterwards. Across replicas,
  reservations are not shared: N replicas can together overshoot by at most
  the cost of the requests in flight at once. That is the honest bound
  without a distributed lock on every request.

## 10. Audit log

Every record carries `seq`, `ts`, `kind`, `actor`, `subject`, `action`,
`resource`, `decision`, `reasons`, `details`, `prev_hash`, `hash`, where
`hash = SHA-256(prev_hash ‖ canonical-json(record-without-hash))`.

* Postgres enforces append-only with a trigger that rejects `UPDATE`, `DELETE`
  and `TRUNCATE` on `audit_log`.
* Record times are stamped while the append lock is held and never run
  backwards, even across replicas with skewed clocks, so any time range is a
  contiguous, verifiable run of sequence numbers.
* `GET /api/audit/export?format=jsonl|csv&from=&to=` streams records;
  `chautari audit verify export.jsonl` re-computes the chain offline. Auditors
  need nothing from us but the file.

## 11. Generator

`chautari generate estate.cdl -o ./out`:

```
out/
├── .chautari/manifest.json      hashes of everything generated
├── estate.json                  compiled estate (canonical JSON)
├── gateway/gateway.yaml         agentgateway (or litellm/config.yaml)
├── policy/                      Rego bundle + data.json
├── otel/collector.yaml
├── docker-compose.yml
├── helm/chautari/               Chart, values, templates
├── terraform/aws/               VPC-agnostic ECS Fargate + RDS + Secrets Manager
└── CONTROLS.md                  controls-mapping report for this estate
```

**Idempotency.** Output is a pure function of the CDL (sorted keys, no
timestamps, no random values). Files are only written when content changes.
The manifest stores each file's hash; if a file on disk no longer matches the
hash we last wrote, someone edited it, and the generator leaves it alone and
says so unless `--force` is given. Running `generate` twice yields zero
changes, and the tests prove it.

## 12. Persistence

Postgres in every real deployment (`CHAUTARI_DATABASE_URL`); schema migrations
are embedded and applied on start under an advisory lock. The in-memory store
implements the same interface and backs the unit tests. The Postgres store has
its own integration tests that run when `CHAUTARI_TEST_DATABASE_URL` is set.

## 13. Security notes

* API keys: `ck_` + 32 random bytes (base62). Stored as SHA-256. Shown once.
* Admin identity. With per-person tokens (`CHAUTARI_ADMIN_TOKENS`,
  `name=token,…`) the token says who is acting: separation of duties is
  enforced and the controls report says so. With a single shared token
  (`CHAUTARI_ADMIN_TOKEN`, for trials) people name themselves and separation
  of duties is advisory, which the controls report also says. OIDC is next.
* Browser sessions: an HMAC-signed, HttpOnly, SameSite=Strict cookie carrying
  the identity and an expiry, never the token. Rotating any admin token signs
  everyone out. State-changing requests from a session must carry a header
  only the admin UI's own scripts can set (CSRF). Failed sign-ins are audited
  and throttled per address.
* Raw prompts and completions are never written to the audit log.
* Production databases: run migrations as a schema-owner role and the control
  plane as a role with only `INSERT`/`SELECT` on `audit_log`, so not even a
  compromised control plane can drop the append-only trigger.
* The gateway's internal key and provider credentials come from the
  environment / Secrets Manager, never from CDL.

## 14. Non-goals and roadmap

Non-goals: being a gateway, being a model host, being an eval platform.

Next: OIDC for the admin plane; Anthropic `/v1/messages` passthrough on the
checkpoint; distributed rate limiting through agentgateway's remote rate
limiter; Kubernetes operator mode reading CDL from a ConfigMap; signed audit
checkpoints anchored externally.
