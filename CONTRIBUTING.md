# Contributing to Chautari

Thank you for your interest in contributing to Chautari.

## Ground rules

- **Every feature ships with tests.** The suite runs offline: if your change
  needs a model provider, extend the mock in `internal/mockllm` instead.
- **Governance code fails closed.** If a policy, guardrail or budget check
  cannot reach a decision, the answer is no. Reviews will ask about it.
- **Don't rebuild what's already open.** Before adding a component, check
  whether agentgateway, OPA or OpenTelemetry already does it.
- **Raw prompts never touch the audit log.** Digests, counts, names only.

## Workflow

```sh
make lint      # gofmt, go vet
make test      # offline suite with the race detector
make test-pg   # + Postgres integration tests (needs Docker)
go run ./tools/licensecheck   # Apache 2.0 headers
```

Every source file carries the Apache 2.0 header; `go run ./tools/licensecheck -fix`
adds it. By contributing you agree your work is licensed under Apache 2.0.

Changing CDL? Update `docs/CDL.md` in the same pull request, with tests for
the new syntax and its error messages. Changing the generated agentgateway
config? The schema test in `internal/dataplane` must still pass against the
pinned upstream schema; bumping agentgateway means vendoring its new schema.

Commits: small, present tense, explain the why. Pull requests: say what you
tested.
