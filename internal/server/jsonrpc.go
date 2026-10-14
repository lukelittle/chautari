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

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// rpcMessage is one JSON-RPC message, parsed strictly.
//
// The checkpoint decides on what it parsed and forwards what it re-encoded
// from the same parse, so a downstream parser can never see a different
// message than the one that was authorised. Ambiguous input that two parsers
// could read differently (duplicate keys, keys differing only in case, which
// Go's encoding/json folds) is refused outright.
type rpcMessage struct {
	raw    map[string]any
	ID     json.RawMessage
	Method string
}

// toolName returns params.name for tools/call.
func (m rpcMessage) toolName() (string, bool) {
	p, ok := m.raw["params"].(map[string]any)
	if !ok {
		return "", false
	}
	n, ok := p["name"].(string)
	return n, ok
}

// canonical re-encodes the parsed message for forwarding.
func (m rpcMessage) canonical() []byte {
	b, _ := json.Marshal(m.raw)
	return b
}

var errBatch = errors.New("JSON-RPC batches are not supported; send one message per request")

// parseRPC strictly parses a single JSON-RPC 2.0 message.
func parseRPC(raw []byte) (rpcMessage, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return rpcMessage{}, errors.New("empty body")
	}
	if trimmed[0] == '[' {
		return rpcMessage{}, errBatch
	}
	if trimmed[0] != '{' {
		return rpcMessage{}, errors.New("body must be a JSON object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := checkUnambiguous(dec); err != nil {
		return rpcMessage{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return rpcMessage{}, errors.New("trailing data after JSON value")
	}
	var m map[string]any
	d2 := json.NewDecoder(bytes.NewReader(trimmed))
	d2.UseNumber()
	if err := d2.Decode(&m); err != nil {
		return rpcMessage{}, err
	}
	if v, _ := m["jsonrpc"].(string); v != "2.0" {
		return rpcMessage{}, errors.New(`jsonrpc must be "2.0"`)
	}
	msg := rpcMessage{raw: m}
	if id, ok := m["id"]; ok {
		msg.ID, _ = json.Marshal(id)
	}
	if meth, ok := m["method"]; ok {
		s, isStr := meth.(string)
		if !isStr || s == "" {
			return rpcMessage{}, errors.New("method must be a non-empty string")
		}
		msg.Method = s
	}
	if msg.Method == "tools/call" {
		if _, ok := msg.toolName(); !ok {
			return rpcMessage{}, errors.New("tools/call needs params.name as a string")
		}
	}
	return msg, nil
}

// checkUnambiguous walks one JSON value and rejects objects with duplicate
// keys or keys that differ only in letter case.
func checkUnambiguous(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]string{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key := kt.(string)
			fold := strings.ToLower(key)
			if prev, dup := seen[fold]; dup {
				if prev == key {
					return fmt.Errorf("duplicate key %q", key)
				}
				return fmt.Errorf("ambiguous keys %q and %q", prev, key)
			}
			seen[fold] = key
			if err := checkUnambiguous(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := checkUnambiguous(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // closing delimiter
	return err
}
