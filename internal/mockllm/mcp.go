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

package mockllm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
)

// MCP server identity and defaults.
const (
	MCPServerName      = "chautari-mock-mcp"
	MCPServerVersion   = "0.1.0"
	MCPProtocolVersion = "2025-06-18"
)

// MCPTools lists the tool names served by the mock MCP server.
var MCPTools = []string{"search_issues", "get_issue", "update_loan"}

var loanStatuses = []string{"pending", "approved", "declined", "on_hold"}

type issue struct {
	Key, Summary, Status, Assignee string
}

var issues = []issue{
	{"LOAN-101", "Income verification missing for application 88231", "In Progress", "a.sharma"},
	{"LOAN-102", "Appraisal report delayed for 14 Elm Street", "Open", "j.okafor"},
	{"OPS-311", "Nightly payments batch exceeded SLA", "Resolved", "m.chen"},
	{"OPS-318", "Reconciliation break on card settlement file", "Open", "m.chen"},
	{"RISK-42", "Model validation evidence for credit scorecard v3", "In Review", "l.garcia"},
}

var sessionSeq atomic.Uint64

func handleMCPMethodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "method not allowed: the mock MCP server does not offer an SSE stream", http.StatusMethodNotAllowed)
}

func (s *server) handleMCP(w http.ResponseWriter, r *http.Request) {
	req, ok := readRPC(w, r)
	if !ok {
		return
	}
	if req.isNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", fmt.Sprintf("mock-session-%d", sessionSeq.Add(1)))
		writeRPCResult(w, req.ID, initializeResult(req.Params))
	case "ping":
		writeRPCResult(w, req.ID, struct{}{})
	case "tools/list":
		writeRPCResult(w, req.ID, map[string]any{"tools": toolDefinitions()})
	case "tools/call":
		res, err := callTool(req.Params)
		if err != nil {
			writeRPCError(w, req.ID, err)
			return
		}
		writeRPCResult(w, req.ID, res)
	default:
		writeRPCError(w, req.ID, &rpcError{rpcMethodNotFound, "Method not found: " + req.Method})
	}
}

func initializeResult(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := p.ProtocolVersion
	if version == "" {
		version = MCPProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": MCPServerName, "version": MCPServerVersion},
	}
}

func toolDefinitions() []map[string]any {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	schema := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
	}
	status := str("New loan status.")
	status["enum"] = loanStatuses
	return []map[string]any{
		{
			"name":        "search_issues",
			"description": "Search Jira issues by free-text query.",
			"inputSchema": schema(map[string]any{"query": str("Text to match against issue keys and summaries.")}, "query"),
		},
		{
			"name":        "get_issue",
			"description": "Fetch a single Jira issue by key.",
			"inputSchema": schema(map[string]any{"key": str("Issue key, e.g. LOAN-101.")}, "key"),
		},
		{
			"name":        "update_loan",
			"description": "Update the status of a loan in the loan origination system.",
			"inputSchema": schema(map[string]any{"loan_id": str("Loan identifier, e.g. L-2024-0001."), "status": status}, "loan_id", "status"),
		},
	}
}

type toolResult struct {
	Content []textContent `json:"content"`
	IsError bool          `json:"isError"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string, isErr bool) toolResult {
	return toolResult{Content: []textContent{{Type: "text", Text: text}}, IsError: isErr}
}

func callTool(params json.RawMessage) (toolResult, *rpcError) {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolResult{}, &rpcError{rpcInvalidParams, "Invalid params: " + err.Error()}
	}
	arg := func(name string) (string, *rpcError) {
		v := p.Arguments[name]
		if v == "" {
			return "", &rpcError{rpcInvalidParams, fmt.Sprintf("Invalid params: %s requires argument %q", p.Name, name)}
		}
		return v, nil
	}
	switch p.Name {
	case "search_issues":
		q, err := arg("query")
		if err != nil {
			return toolResult{}, err
		}
		return textResult(searchIssues(q), false), nil
	case "get_issue":
		key, err := arg("key")
		if err != nil {
			return toolResult{}, err
		}
		return textResult(formatIssue(lookupIssue(key)), false), nil
	case "update_loan":
		id, err := arg("loan_id")
		if err != nil {
			return toolResult{}, err
		}
		st, err := arg("status")
		if err != nil {
			return toolResult{}, err
		}
		if !slices.Contains(loanStatuses, st) {
			return textResult(fmt.Sprintf("Invalid status %q; expected one of %s.", st, strings.Join(loanStatuses, ", ")), true), nil
		}
		return textResult(fmt.Sprintf("Loan %s status updated to %s. Change reference CHG-%s.", id, st, shortHash(8, id, st)), false), nil
	default:
		return toolResult{}, &rpcError{rpcInvalidParams, "Unknown tool: " + p.Name}
	}
}

func searchIssues(query string) string {
	q := strings.ToLower(query)
	var lines []string
	for _, is := range issues {
		if strings.Contains(strings.ToLower(is.Key+" "+is.Summary), q) {
			lines = append(lines, formatIssue(is))
		}
	}
	if len(lines) == 0 {
		return fmt.Sprintf("No issues match %q.", query)
	}
	return fmt.Sprintf("Found %d issue(s):\n%s", len(lines), strings.Join(lines, "\n"))
}

// lookupIssue returns a known issue, or a deterministic synthetic one for unknown keys.
func lookupIssue(key string) issue {
	for _, is := range issues {
		if strings.EqualFold(is.Key, key) {
			return is
		}
	}
	h := shortHash(8, key)
	statuses := []string{"Open", "In Progress", "Resolved"}
	return issue{Key: key, Summary: "Follow-up item " + h, Status: statuses[int(h[0])%len(statuses)], Assignee: "unassigned"}
}

func formatIssue(is issue) string {
	return fmt.Sprintf("%s [%s] %s (assignee: %s)", is.Key, is.Status, is.Summary, is.Assignee)
}
