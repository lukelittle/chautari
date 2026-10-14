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

# Policy unit tests: `opa test internal/policy/rego` runs these too.
package chautari.authz_test

import rego.v1

import data.chautari.authz

estate := {
	"teams": {"lending": {"name": "lending", "models": ["sonnet"], "tools": ["jira"], "clearance": "confidential"}},
	"models": {
		"sonnet": {"name": "sonnet", "status": "approved", "data_class": "confidential"},
		"llama": {"name": "llama", "status": "requested", "data_class": "public"},
	},
	"tools": {"jira": {"name": "jira", "status": "approved", "data_class": "internal", "allow": ["get_issue"]}},
	"agents": {},
}

req(action, name, dc) := {"subject": {"team": "lending"}, "action": action, "resource": {"name": name}, "data_class": dc}

test_allow_entitled_model if {
	authz.decision.allow with input as req("model.invoke", "sonnet", "confidential") with data.estate as estate
}

test_public_data_is_rank_zero if {
	authz.decision.allow with input as req("model.invoke", "sonnet", "public") with data.estate as estate
}

test_deny_unapproved_model if {
	d := authz.decision with input as req("model.invoke", "llama", "public") with data.estate as estate
	not d.allow
	"model \"llama\" is requested, not approved" in d.reasons
}

test_deny_restricted_data if {
	d := authz.decision with input as req("model.invoke", "sonnet", "restricted") with data.estate as estate
	not d.allow
	count(d.reasons) == 2
}

test_deny_tool_outside_allow_list if {
	r := object.union(req("tool.call", "jira", "internal"), {"resource": {"name": "jira", "tool": "delete_issue"}})
	d := authz.decision with input as r with data.estate as estate
	not d.allow
}

test_custom_rules_deny if {
	d := authz.decision with input as req("model.invoke", "sonnet", "internal") with data.estate as estate
		with data.chautari.custom.deny as {"after hours"}
	not d.allow
	d.reasons == ["after hours"]
}

test_deny_missing_tool_name_when_allow_listed if {
	d := authz.decision with input as req("tool.call", "jira", "internal") with data.estate as estate
	not d.allow
}
