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
)

// JSON-RPC 2.0 error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the request carries no id.
func (r *rpcRequest) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return e.Message }

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// readRPC decodes a single JSON-RPC request. On failure it writes the error
// response and returns false.
func readRPC(w http.ResponseWriter, r *http.Request) (*rpcRequest, bool) {
	var req rpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeRPCError(w, nil, &rpcError{rpcParseError, "Parse error: " + err.Error()})
		return nil, false
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeRPCError(w, req.ID, &rpcError{rpcInvalidRequest, "Invalid Request: jsonrpc must be \"2.0\" and method is required"})
		return nil, false
	}
	return &req, true
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: rpcID(id), Result: result})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, e *rpcError) {
	writeJSON(w, http.StatusOK, rpcResponse{JSONRPC: "2.0", ID: rpcID(id), Error: e})
}

func rpcID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}
