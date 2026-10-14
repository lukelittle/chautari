#!/usr/bin/env bash
#
# Copyright 2026 the original author or authors from the Chautari project.
#
# This file is part of the Chautari project, see https://github.com/lukelittle/chautari
# for more information.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# End-to-end test against a real agentgateway binary:
#
#   app → chautari checkpoint → agentgateway (config rendered by chautari) → mock provider
#
# Usage: AGENTGATEWAY=/path/to/agentgateway scripts/e2e-agentgateway.sh
# Needs: go, curl, jq. Uses ports 18080 (chautari), 13000/13100 (gateway), 18090 (mock).

set -uo pipefail
cd "$(dirname "$0")/.."

AGW="${AGENTGATEWAY:-agentgateway}"
command -v "$AGW" >/dev/null || { echo "agentgateway binary not found (set AGENTGATEWAY)"; exit 2; }
command -v jq >/dev/null || { echo "jq is required"; exit 2; }

WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

pass=0; fail=0
check() { # name, condition result (0 = ok)
  if [ "$2" = 0 ]; then printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1));
  else printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail+1)); fi
}

echo "building chautari and mock-llm"
go build -o "$WORK/chautari" ./cmd/chautari
go build -o "$WORK/mock-llm" ./cmd/mock-llm

# The example estate, pointed at local ports instead of compose service names.
sed -e 's#http://mock-llm:8090#http://127.0.0.1:18090#g' -e 's#"mock-llm:8090"#"127.0.0.1:18090"#g' \
  examples/himalayan-bank.cdl > "$WORK/estate.cdl"

export CHAUTARI_GATEWAY_KEY="e2e-internal-key"
ADMIN="e2e-admin-token"

MOCK_LLM_ADDR=127.0.0.1:18090 "$WORK/mock-llm" > "$WORK/mock.log" 2>&1 & PIDS+=($!)

# prep stands in for the shared volume: it remaps the gateway's ports so they
# don't collide with anything local and, where the host has no IPv6 (some CI
# sandboxes), turns IPv6 off. Everything else is exactly what chautari wrote.
prep() { # src dst
  { if [ "${E2E_NO_IPV6:-0}" = 1 ]; then printf 'config:\n  enableIpv6: false\n'; fi
    sed -e 's/port: 3000/port: 13000/' -e 's/port: 3100/port: 13100/' "$1"; } > "$2.tmp" && mv "$2.tmp" "$2"
}

# Render the initial gateway config from CDL alone, as the init container does.
mkdir -p "$WORK/gw"
"$WORK/chautari" render-gateway --estate "$WORK/estate.cdl" --out "$WORK/gw/initial.yaml"
prep "$WORK/gw/initial.yaml" "$WORK/gw/gateway.yaml"
"$AGW" -f "$WORK/gw/gateway.yaml" > "$WORK/agw.log" 2>&1 & PIDS+=($!)

"$WORK/chautari" serve --estate "$WORK/estate.cdl" --addr 127.0.0.1:18080 --admin-token "$ADMIN" \
  --gateway-url http://127.0.0.1:13000 --gateway-a2a-url http://127.0.0.1:13100 \
  --gateway-config "$WORK/gw/live.yaml" > "$WORK/chautari.log" 2>&1 & PIDS+=($!)

for i in $(seq 1 60); do
  curl -sf http://127.0.0.1:18080/healthz >/dev/null && curl -s -o /dev/null http://127.0.0.1:13000/ && break
  sleep 0.5
done

api() { curl -s -H "Authorization: Bearer $ADMIN" -H "X-Chautari-Actor: e2e@chautari" "$@"; }
KEY=$(api http://127.0.0.1:18080/api/keys -d '{"app":"loan-assistant"}' | jq -r .secret)
WKEY=$(api http://127.0.0.1:18080/api/keys -d '{"app":"advisor-copilot"}' | jq -r .secret)
chat() { curl -s -o "$WORK/out.json" -w '%{http_code}' http://127.0.0.1:18080/v1/chat/completions -H "Authorization: Bearer $1" "${@:3}" -d "$2"; }

echo
echo "agentgateway $("$AGW" --version 2>/dev/null | grep -o '"version": *"[^"]*"' | head -1)"
echo "LLM through the gateway"
code=$(chat "$KEY" '{"model":"claude-sonnet","messages":[{"role":"user","content":"Summarise the loan file for jane@example.com"}]}')
check "allowed request reaches the mock through agentgateway (HTTP $code)" "$([ "$code" = 200 ] && jq -e '.choices[0].message.content|length>0' "$WORK/out.json" >/dev/null && echo 0 || echo 1)"
check "gateway mapped the model name to the upstream id" "$(jq -e '.model=="claude-sonnet-4-5"' "$WORK/out.json" >/dev/null && echo 0 || echo 1)"
code=$(chat "$KEY" '{"model":"claude-sonnet","stream":true,"messages":[{"role":"user","content":"stream please"}]}')
check "streaming through the gateway (HTTP $code)" "$([ "$code" = 200 ] && grep -q '\[DONE\]' "$WORK/out.json" && echo 0 || echo 1)"
code=$(chat "$KEY" '{"model":"claude-sonnet","messages":[{"role":"user","content":"read it back [[leak-ssn]]"}]}')
check "outbound SSN withheld after the gateway answered (HTTP $code)" "$([ "$code" = 502 ] && echo 0 || echo 1)"

echo "The gateway only trusts the checkpoint"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:13000/v1/chat/completions -d '{"model":"claude-sonnet","messages":[{"role":"user","content":"hi"}]}')
check "direct call without the internal key is refused (HTTP $code)" "$([ "$code" = 401 ] || [ "$code" = 403 ] && echo 0 || echo 1)"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:13000/v1/chat/completions -H "Authorization: Bearer $KEY" -d '{"model":"claude-sonnet","messages":[{"role":"user","content":"hi"}]}')
check "an app key is not accepted by the gateway (HTTP $code)" "$([ "$code" = 401 ] || [ "$code" = 403 ] && echo 0 || echo 1)"

echo "MCP through the gateway"
# mcp_session URL BEARER [extra curl args...]: initialize, then echo the session id.
mcp_session() {
  local url=$1 bearer=$2; shift 2
  local sid
  sid=$(curl -s -D - -o /dev/null "$url" -H "Authorization: Bearer $bearer" "$@" \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}' \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}')
  curl -s -o /dev/null "$url" -H "Authorization: Bearer $bearer" "$@" -H "Mcp-Session-Id: $sid" \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo "$sid"
}
# mcp_call URL BEARER SID JSON [extra curl args...]
mcp_call() {
  local url=$1 bearer=$2 sid=$3 body=$4; shift 4
  curl -s "$url" -H "Authorization: Bearer $bearer" -H "Mcp-Session-Id: $sid" "$@" \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -d "$body"
}
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_issue","arguments":{"key":"LOAN-101"}}}'
LIST='{"jsonrpc":"2.0","id":3,"method":"tools/list"}'

SID=$(mcp_session http://127.0.0.1:18080/mcp "$KEY")
check "MCP session established through checkpoint and gateway" "$([ -n "$SID" ] && echo 0 || echo 1)"
out=$(mcp_call http://127.0.0.1:18080/mcp "$KEY" "$SID" "$CALL")
check "entitled tool call returns data" "$(echo "$out" | grep -q 'LOAN-101' && echo 0 || echo 1)"
out=$(mcp_call http://127.0.0.1:18080/mcp "$KEY" "$SID" "$LIST")
check "tools/list shows only the allow-listed tools" "$(echo "$out" | grep -q 'get_issue' && ! echo "$out" | grep -q 'update_loan' && echo 0 || echo 1)"
WSID=$(mcp_session http://127.0.0.1:18080/mcp "$WKEY")
out=$(mcp_call http://127.0.0.1:18080/mcp "$WKEY" "$WSID" "$CALL")
check "unentitled team is refused at the checkpoint" "$(echo "$out" | grep -q 'Chautari policy' && echo 0 || echo 1)"
# Defence in depth: skip the checkpoint, call the gateway with the internal key
# claiming a team the CEL rules don't entitle. The gateway itself must refuse.
GSID=$(mcp_session http://127.0.0.1:13000/mcp "$CHAUTARI_GATEWAY_KEY" -H 'X-Chautari-Team: wealth')
out=$(mcp_call http://127.0.0.1:13000/mcp "$CHAUTARI_GATEWAY_KEY" "$GSID" "$CALL" -H 'X-Chautari-Team: wealth')
check "gateway session for the bypass attempt established" "$([ -n "$GSID" ] && echo 0 || echo 1)"
check "the gateway's own CEL rules refuse an unentitled team" "$(echo "$out" | grep -q 'LOAN-101' && echo 1 || echo 0)"
out=$(mcp_call http://127.0.0.1:13000/mcp "$CHAUTARI_GATEWAY_KEY" "$GSID" "$LIST" -H 'X-Chautari-Team: wealth')
check "and hide the tools from its tools/list" "$(echo "$out" | grep -q 'get_issue' && echo 1 || echo 0)"
LSID=$(mcp_session http://127.0.0.1:13000/mcp "$CHAUTARI_GATEWAY_KEY" -H 'X-Chautari-Team: lending')
out=$(mcp_call http://127.0.0.1:13000/mcp "$CHAUTARI_GATEWAY_KEY" "$LSID" "$CALL" -H 'X-Chautari-Team: lending')
check "while the entitled team is allowed by the same rules" "$(echo "$out" | grep -q 'LOAN-101' && echo 0 || echo 1)"

echo "A2A through the gateway"
code=$(curl -s -o "$WORK/a2a.json" -w '%{http_code}' http://127.0.0.1:18080/a2a/underwriting-agent/ -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m1","parts":[{"kind":"text","text":"memo for LOAN-102"}]}}}')
check "agent call routed (HTTP $code)" "$([ "$code" = 200 ] && grep -q 'Credit memo draft' "$WORK/a2a.json" && echo 0 || echo 1)"

echo "Kill switch: retire, the gateway hot-reloads"
# chautari writes the live config to live.yaml; this script remaps its ports
# and moves it into place, standing in for the shared volume.
api -X POST http://127.0.0.1:18080/api/registry/model/claude-sonnet/retire -d '{"note":"e2e"}' >/dev/null
sleep 0.5
prep "$WORK/gw/live.yaml" "$WORK/gw/gateway.yaml"
reloaded=1
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:13000/v1/chat/completions -H "Authorization: Bearer $CHAUTARI_GATEWAY_KEY" -d '{"model":"claude-sonnet","messages":[{"role":"user","content":"hi"}]}')
  [ "$code" != 200 ] && { reloaded=0; break; }
  sleep 0.5
done
check "retired model no longer routable in agentgateway after hot reload" "$reloaded"
code=$(chat "$KEY" '{"model":"claude-sonnet","messages":[{"role":"user","content":"hi"}]}')
check "and refused by policy at the checkpoint (HTTP $code)" "$([ "$code" = 403 ] && echo 0 || echo 1)"

echo "Audit"
api http://127.0.0.1:18080/api/audit/export > "$WORK/audit.jsonl"
"$WORK/chautari" audit verify "$WORK/audit.jsonl" >/dev/null; rc=$?
check "audit export verifies offline" "$rc"

echo
echo "$pass passed, $fail failed"
if [ "$fail" != 0 ]; then
  echo "--- agentgateway log (tail) ---"; tail -30 "$WORK/agw.log"
  echo "--- chautari log (tail) ---"; tail -10 "$WORK/chautari.log"
  exit 1
fi
