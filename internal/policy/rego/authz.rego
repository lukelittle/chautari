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

# Chautari authorization policy.
#
# data.estate is the compiled CDL plus live registry state (see
# internal/policy/data.go). input is one access request:
#
#   {
#     "subject":    {"team": "lending", "app": "loan-assistant", "key": "key_…"},
#     "action":     "model.invoke" | "tool.call" | "agent.call",
#     "resource":   {"name": "claude-sonnet", "tool": "get_issue"},
#     "data_class": "internal"
#   }
#
# Every rule below is a reason to say no. If none fire, the answer is yes.
# Operators add their own reasons in package chautari.custom (--policy-dir).
package chautari.authz

import rego.v1

rank := {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

team := data.estate.teams[input.subject.team]

decision := {
	"allow": count(reasons) == 0,
	"reasons": sort(reasons),
}

reasons := deny | {m | some m in data.chautari.custom.deny}

# ── subject ────────────────────────────────────────────────────────────────

deny contains sprintf("unknown team %q", [input.subject.team]) if {
	not data.estate.teams[input.subject.team]
}

deny contains sprintf("unknown data class %q", [input.data_class]) if {
	not rank[input.data_class]
}

deny contains sprintf("team %q is cleared for %s data, not %s", [team.name, team.clearance, input.data_class]) if {
	rank[input.data_class] > rank[team.clearance]
}

deny contains sprintf("unknown action %q", [input.action]) if {
	not input.action in {"model.invoke", "tool.call", "agent.call"}
}

# ── models ─────────────────────────────────────────────────────────────────

model := data.estate.models[input.resource.name]

deny contains sprintf("model %q is not in the registry", [input.resource.name]) if {
	input.action == "model.invoke"
	not data.estate.models[input.resource.name]
}

deny contains sprintf("model %q is %s, not approved", [model.name, model.status]) if {
	input.action == "model.invoke"
	model.status != "approved"
}

deny contains sprintf("team %q is not entitled to model %q", [team.name, model.name]) if {
	input.action == "model.invoke"
	not model.name in team.models
}

deny contains sprintf("model %q is approved for %s data, not %s", [model.name, model.data_class, input.data_class]) if {
	input.action == "model.invoke"
	rank[input.data_class] > rank[model.data_class]
}

# ── tools ──────────────────────────────────────────────────────────────────

tool := data.estate.tools[input.resource.name]

deny contains sprintf("tool %q is not in the registry", [input.resource.name]) if {
	input.action == "tool.call"
	not data.estate.tools[input.resource.name]
}

deny contains sprintf("tool %q is %s, not approved", [tool.name, tool.status]) if {
	input.action == "tool.call"
	tool.status != "approved"
}

deny contains sprintf("team %q is not entitled to tool %q", [team.name, tool.name]) if {
	input.action == "tool.call"
	not tool.name in team.tools
}

deny contains sprintf("tool %q exposes named tools only; say which one", [tool.name]) if {
	input.action == "tool.call"
	count(tool.allow) > 0
	object.get(input.resource, "tool", "") == ""
}

deny contains sprintf("tool %q does not expose %q", [tool.name, input.resource.tool]) if {
	input.action == "tool.call"
	count(tool.allow) > 0
	input.resource.tool
	not input.resource.tool in tool.allow
}

deny contains sprintf("tool %q is approved for %s data, not %s", [tool.name, tool.data_class, input.data_class]) if {
	input.action == "tool.call"
	rank[input.data_class] > rank[tool.data_class]
}

# ── agents ─────────────────────────────────────────────────────────────────

agent := data.estate.agents[input.resource.name]

deny contains sprintf("agent %q is not in the registry", [input.resource.name]) if {
	input.action == "agent.call"
	not data.estate.agents[input.resource.name]
}

deny contains sprintf("agent %q is %s, not approved", [agent.name, agent.status]) if {
	input.action == "agent.call"
	agent.status != "approved"
}

deny contains sprintf("agent %q belongs to team %q", [agent.name, agent.team]) if {
	input.action == "agent.call"
	agent.team != input.subject.team
}
