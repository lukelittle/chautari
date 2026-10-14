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
	"net/http"
	"strings"
)

// A2A agent identity.
const (
	AgentName            = "underwriting-agent"
	AgentVersion         = "0.1.0"
	A2AProtocolVersion   = "0.3.0"
	CreditMemoReplyStart = "Credit memo draft: "
)

func handleAgentCard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":               AgentName,
		"description":        "Mock underwriting agent that drafts credit memos for loan applications.",
		"url":                baseURL(r) + "/",
		"version":            AgentVersion,
		"protocolVersion":    A2AProtocolVersion,
		"preferredTransport": "JSONRPC",
		"capabilities":       map[string]any{"streaming": false},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"skills": []map[string]any{{
			"id":          "credit-memo",
			"name":        "Draft credit memo",
			"description": "Drafts a credit memo summarising a borrower's application, risks and recommendation.",
			"tags":        []string{"underwriting", "credit", "lending"},
			"examples":    []string{"Draft a credit memo for application 88231."},
		}},
	})
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

type a2aPart struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
}

type a2aMessage struct {
	Kind      string    `json:"kind"`
	Role      string    `json:"role"`
	MessageID string    `json:"messageId"`
	ContextID string    `json:"contextId,omitempty"`
	Parts     []a2aPart `json:"parts"`
}

func handleA2A(w http.ResponseWriter, r *http.Request) {
	req, ok := readRPC(w, r)
	if !ok {
		return
	}
	if req.Method != "message/send" {
		writeRPCError(w, req.ID, &rpcError{rpcMethodNotFound, "Method not found: " + req.Method})
		return
	}
	var p struct {
		Message *a2aMessage `json:"message"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Message == nil {
		writeRPCError(w, req.ID, &rpcError{rpcInvalidParams, "Invalid params: message is required"})
		return
	}
	var texts []string
	for _, part := range p.Message.Parts {
		if part.Kind == "text" {
			texts = append(texts, part.Text)
		}
	}
	input := strings.Join(texts, "\n")
	writeRPCResult(w, req.ID, a2aMessage{
		Kind:      "message",
		Role:      "agent",
		MessageID: "msg-mock-" + shortHash(12, input),
		ContextID: p.Message.ContextID,
		Parts:     []a2aPart{{Kind: "text", Text: creditMemo(input)}},
	})
}

func creditMemo(input string) string {
	subject := strings.TrimSpace(input)
	if subject == "" {
		subject = "the application"
	}
	return CreditMemoReplyStart + "Request: " + subject + ". Borrower shows stable income and a debt-to-income ratio of 31%. " +
		"Collateral coverage is adequate at 1.4x. Key risk: concentration in a single employer. " +
		"Recommendation: approve subject to standard covenants. Ref " + shortHash(8, input) + "."
}
