# CDL: the Chautari Definition Language

CDL describes an organisation's AI estate in one reviewable file. The syntax
is straightforward: a handful of declaration kinds, each with a name and a
block of properties.

```cdl
// estate.cdl
estate himalayan-bank { org "Himalayan Bank", dataplane agentgateway, region us-east-1 }

provider bedrock { type bedrock, region us-east-1 }

model claude-sonnet { provider bedrock, id "anthropic.claude-sonnet-4-5-v1:0",
                      approved true, data-class internal,
                      cost-in 3 usd/mtok, cost-out 15 usd/mtok }

tool jira-mcp { endpoint "http://jira-mcp:8080/mcp", scope read, owners [platform-team] }

policy pii { redact inbound, block outbound ssn, card }

team lending { models [claude-sonnet], budget 2000 usd/month, tools [jira-mcp] }
```

## Lexical structure

| Token | Form | Examples |
|---|---|---|
| identifier | `[A-Za-z_]([A-Za-z0-9_.-]*[A-Za-z0-9_])?` | `claude-sonnet`, `us-east-1`, `gpt-4o.mini` |
| string | `"…"` on one line, with `\"` and `\\` escapes | `"Himalayan Bank"` |
| number | digits, optional fraction, optional `k`/`K`/`m`/`M` suffix | `2000`, `0.25`, `20k`, `1.5M` |
| punctuation | `{ } [ ] , /` | |
| comment | `// …`, `# …`, `/* … */` | |

`true`/`false` are identifiers that the validator reads as booleans.
Identifiers may contain `.` and `-` so model IDs and regions read naturally,
but cannot end in either: in `foo-` the identifier is `foo` and the `-` is an
error. Identifiers are ASCII. A Unicode letter in one is an error, because a
look-alike (`tеam` with a Cyrillic `е`) would otherwise name a different team;
display names go in strings. Declaration names are at most 63 characters.
Anything else goes in a string.

Strings may contain any Unicode text except:

* control characters, including newlines and tabs (there are no `\n` or `\t`
  escapes);
* the sequences `{{`, `}}`, `[[`, `]]` and `${`.

Strings are copied into generated YAML, Helm templates (which evaluate
`{{ }}`, even in `NOTES.txt`), Go templates and agentgateway's config (which
expands `${VAR}`), and these would break out of them or be expanded. The
error names the offending property.

## Grammar (EBNF)

```ebnf
file         = { declaration } EOF ;
declaration  = kind name block ;
kind         = "estate" | "provider" | "model" | "tool" | "agent"
             | "team" | "app" | "policy" ;
name         = IDENT ;
block        = "{" [ property { "," property } [ "," ] ] "}" ;
property     = key value { value } { "," continuation } ;
key          = IDENT ;                      (* must be a known key for the kind *)
continuation = atom ;                       (* see "bare lists" below *)
value        = atom | list | quantity ;
atom         = IDENT | STRING | NUMBER ;
quantity     = NUMBER IDENT "/" IDENT ;     (* 2000 usd/month, 20k tokens/min *)
list         = "[" [ value { "," value } [ "," ] ] "]" ;
```

### Bare lists

Commas separate properties, and they also separate items of a bare list:

```cdl
policy pii { redact inbound, block outbound ssn, card }
```

After a comma the parser looks at the next identifier. If it is a known key for
the declaration kind (`block` is a key of `policy`), a new property starts.
Otherwise the token is appended to the previous property's values (`card`
joins `block outbound ssn`). This keeps the one-liners readable without
ambiguity, because keys and values never share a name within a kind. Brackets
always work too: `block outbound [ssn, card]`.

Repeating a key starts a new, independent property. `block outbound ssn,
block card` is two directives, and the second is an error because it has no
direction; it does not inherit `outbound`.

## Declarations

Every name is unique within its kind. References are checked: a team that names
a model that doesn't exist is a compile error, with a "did you mean" hint.

### `estate` (at most one)

| Key | Value | Default |
|---|---|---|
| `org` | string | estate name |
| `dataplane` | `agentgateway` \| `litellm` | `agentgateway` |
| `region` | AWS region | `us-east-1` |
| `default-data-class` | data class | `internal` |
| `environment` | identifier | `dev` |

### `provider`

| Key | Value | Notes |
|---|---|---|
| `type` | `bedrock` \| `openai` \| `anthropic` \| `azure` \| `vertex` \| `openai-compatible` | required |
| `region` | identifier/string | Bedrock and Vertex |
| `endpoint` | string `http(s)://` URL | required for `openai-compatible`; required and `https://` for `azure` |
| `api-key-env` | identifier | env var the data plane reads, default `<NAME>_API_KEY`; must match `[A-Z_][A-Z0-9_]*` |

### `model`

| Key | Value | Default |
|---|---|---|
| `provider` | provider ref | required |
| `id` | upstream model id | the model name |
| `approved` | `true` \| `false` | `false` → enters the registry as `requested` |
| `data-class` | `public` \| `internal` \| `confidential` \| `restricted` | `internal` |
| `cost-in` | quantity `usd/mtok` | `0` |
| `cost-out` | quantity `usd/mtok` | `0` |
| `risk-tier` | `low` \| `medium` \| `high` | `medium` |
| `owner` | team ref | none |
| `description` | string | |

`data-class` on a model is the most sensitive data that model is approved to
receive.

### `tool` (MCP server)

| Key | Value | Default |
|---|---|---|
| `endpoint` | string URL of the MCP server | required |
| `scope` | `read` \| `write` \| `admin` | `read` |
| `owners` | list of team refs | |
| `allow` | non-empty list of tool names exposed | all (omit `allow`) |
| `approved` | bool | `false` |
| `data-class` | data class | `internal` |
| `description` | string | |

A tool's name cannot contain `_`: agentgateway exposes tools as
`<tool server>_<tool>` and splits at the first `_`. Use `-` (`jira-mcp`). Names
in `allow` are the server's own tool names and may contain `_`. An empty
`allow []` is an error rather than "expose everything"; omit `allow` for that.

### `agent` (A2A)

| Key | Value |
|---|---|
| `team` | team ref (required) |
| `model` | model ref |
| `tools` | list of tool refs |
| `endpoint` | string: `host:port` or `http(s)://host[:port][/path]` of the A2A server |
| `approved` | bool |
| `description` | string |

An agent's tools and model must be entitled to its team.

The endpoint may not carry a query string, fragment or credentials. In the
generated gateway config a URL without a port uses the scheme's default (80 or
443), a path is applied with a URL rewrite, and `https://` turns on backend
TLS.

### `team`

| Key | Value |
|---|---|
| `models` | list of model refs |
| `tools` | list of tool refs |
| `budget` | quantity `usd/day` \| `usd/week` \| `usd/month` |
| `rate` | quantity `tokens/min` \| `tokens/hour` \| `requests/min` \| `requests/hour` (repeatable, at most one per unit and period) |
| `clearance` | data class, default `internal` |
| `owner` | string (email) |

### `app`

| Key | Value |
|---|---|
| `team` | team ref (required) |
| `budget` | spend quantity |
| `rate` | rate quantity |
| `key-budget` | spend quantity applied to each key issued for the app |
| `data-class` | default data class for its requests |
| `description` | string |

### `policy` (guardrails)

| Key | Value |
|---|---|
| `redact` | direction, then detectors |
| `block` | direction, then detectors |
| `flag` | direction, then detectors |
| `topics` | non-empty list of non-blank strings, used by the `topic` detector |
| `applies-to` | non-empty list of team refs (omit it for every team) |
| `bedrock-guardrail` | string guardrail id; adds the `bedrock` detector |
| `bedrock-version` | string, default `"DRAFT"` |
| `description` | string |

Directions: `inbound` (prompt), `outbound` (completion), `both`.

Detectors: `ssn`, `card`, `email`, `phone`, `iban`, `aws-key`, `pii` (all of the
above), `injection`, `topic`, `bedrock`. A directive with no detectors means
`pii`.

When several directives match the same finding, the strongest action wins:
`block > redact > flag`.

Topics match as whole words, ignoring case and runs of whitespace. A word
boundary is required only at an edge that is a letter, combining mark, digit
or `_`, so `401(k)`, `C++`, `.NET`, `café` and non-Latin scripts all match as
written.

## Quantities

| Unit | Meaning |
|---|---|
| `usd/day`, `usd/week`, `usd/month` | spend budget, calendar windows in UTC |
| `usd/mtok` | price per million tokens |
| `tokens/min`, `tokens/hour` | token rate limit |
| `requests/min`, `requests/hour` | request rate limit |

Numbers accept `k` (×1,000) and `m` (×1,000,000), in either case:
`20k tokens/min`, `1.5M usd/mtok`.

A rate limit must be a whole number after scaling (`1.5k tokens/min` is 1500;
`1.9 requests/min` is an error). A team or app may set each unit and period
once: two `tokens/min` limits is an error.

## Errors

Errors carry `file:line:col` and a hint:

```
estate.cdl:14:22: team "lending" references unknown model "claude-sonet"
    did you mean "claude-sonnet"?
```

`chautari validate estate.cdl` prints them all, not just the first.
