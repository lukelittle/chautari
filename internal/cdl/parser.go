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

package cdl

import (
	"fmt"
	"strconv"
	"strings"
)

// File is the syntax tree of a CDL file.
type File struct {
	Name  string
	Decls []*Decl
}

// Decl is one top-level declaration: `kind name { ... }`.
type Decl struct {
	Kind  string
	Name  string
	Pos   Pos
	Props []*Prop
}

// Prop is a property: a key followed by one or more values.
type Prop struct {
	Key    string
	Pos    Pos
	Values []Value
}

// ValueKind discriminates Value.
type ValueKind int

const (
	VIdent ValueKind = iota
	VString
	VNumber
	VQuantity
	VList
)

func (k ValueKind) String() string {
	return [...]string{"identifier", "string", "number", "quantity", "list"}[k]
}

// Value is an atom, a quantity (`2000 usd/month`) or a list.
type Value struct {
	Kind  ValueKind
	Pos   Pos
	Text  string  // identifier or string contents
	Num   float64 // number or quantity magnitude
	Unit  string  // quantity numerator, e.g. "usd"
	Per   string  // quantity denominator, e.g. "month"
	Items []Value // list items
}

func (v Value) String() string {
	switch v.Kind {
	case VString:
		return strconv.Quote(v.Text)
	case VNumber:
		return strconv.FormatFloat(v.Num, 'f', -1, 64)
	case VQuantity:
		return fmt.Sprintf("%s %s/%s", strconv.FormatFloat(v.Num, 'f', -1, 64), v.Unit, v.Per)
	case VList:
		parts := make([]string, len(v.Items))
		for i, it := range v.Items {
			parts[i] = it.String()
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return v.Text
}

// Kinds lists declaration kinds in documentation order.
var Kinds = []string{"estate", "provider", "model", "tool", "agent", "team", "app", "policy"}

// keys is the set of valid property keys per declaration kind. It drives both
// validation and the bare-list continuation rule (see docs/CDL.md).
var keys = map[string][]string{
	"estate":   {"org", "dataplane", "region", "default-data-class", "environment"},
	"provider": {"type", "region", "endpoint", "api-key-env"},
	"model":    {"provider", "id", "approved", "data-class", "cost-in", "cost-out", "risk-tier", "owner", "description"},
	"tool":     {"endpoint", "scope", "owners", "allow", "approved", "data-class", "description"},
	"agent":    {"team", "model", "tools", "endpoint", "approved", "description"},
	"team":     {"models", "tools", "budget", "rate", "clearance", "owner"},
	"app":      {"team", "budget", "rate", "key-budget", "data-class", "description"},
	"policy":   {"redact", "block", "flag", "topics", "applies-to", "bedrock-guardrail", "bedrock-version", "description"},
}

func isKey(kind, k string) bool {
	for _, x := range keys[kind] {
		if x == k {
			return true
		}
	}
	return false
}

type parser struct {
	toks []token
	i    int
	file string
	errs *ErrorList
}

// Parse parses CDL source into a syntax tree. It reports every syntax error
// it can recover from rather than stopping at the first.
func Parse(file, src string) (*File, error) {
	var errs ErrorList
	toks := lex(file, src, &errs)
	p := &parser{toks: toks, file: file, errs: &errs}
	f := p.parseFile()
	return f, errs.err()
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) peekAt(n int) token {
	if p.i+n < len(p.toks) {
		return p.toks[p.i+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func (p *parser) errorf(pos Pos, hint, format string, args ...any) {
	p.errs.add(p.file, pos, fmt.Sprintf(format, args...), hint)
}

func (p *parser) parseFile() *File {
	f := &File{Name: p.file}
	for p.peek().kind != tEOF {
		if d := p.parseDecl(); d != nil {
			f.Decls = append(f.Decls, d)
		}
	}
	return f
}

// syncTo skips tokens until the next plausible declaration start.
func (p *parser) syncTo() {
	depth := 0
	for {
		t := p.peek()
		switch t.kind {
		case tEOF:
			return
		case tLBrace:
			depth++
		case tRBrace:
			depth--
			if depth <= 0 {
				p.next()
				return
			}
		case tIdent:
			if depth == 0 && isKind(t.text) && p.peekAt(1).kind == tIdent {
				return
			}
		}
		p.next()
	}
}

func isKind(s string) bool {
	for _, k := range Kinds {
		if k == s {
			return true
		}
	}
	return false
}

func (p *parser) parseDecl() *Decl {
	kt := p.next()
	if kt.kind != tIdent || !isKind(kt.text) {
		hint := ""
		if kt.kind == tIdent {
			hint = suggest(kt.text, Kinds)
		}
		p.errorf(kt.pos, hint, "expected a declaration (estate, provider, model, tool, agent, team, app, policy), found %s", kt.describe())
		p.syncTo()
		return nil
	}
	nt := p.next()
	if nt.kind != tIdent {
		p.errorf(nt.pos, "", "expected a name after %q, found %s", kt.text, nt.describe())
		p.syncTo()
		return nil
	}
	d := &Decl{Kind: kt.text, Name: nt.text, Pos: kt.pos}
	if lb := p.next(); lb.kind != tLBrace {
		p.errorf(lb.pos, "", "expected '{' after %s %s, found %s", kt.text, nt.text, lb.describe())
		p.syncTo()
		return d
	}
	for {
		t := p.peek()
		if t.kind == tRBrace {
			p.next()
			return d
		}
		if t.kind == tEOF {
			p.errorf(d.Pos, "add a closing '}'", "%s %s is never closed", d.Kind, d.Name)
			return d
		}
		prop := p.parseProp(d)
		if prop == nil {
			// Skip to the next comma or closing brace.
			for p.peek().kind != tComma && p.peek().kind != tRBrace && p.peek().kind != tEOF {
				p.next()
			}
		} else {
			d.Props = append(d.Props, prop)
		}
		// Property separator, with bare-list continuation.
		for p.peek().kind == tComma {
			p.next()
			if p.peek().kind == tRBrace {
				break // trailing comma
			}
			if prop != nil && p.continuesList(d.Kind) {
				prop.Values = append(prop.Values, p.parseValue())
				continue
			}
			break
		}
	}
}

// continuesList decides the bare-list rule at the token after a comma. The
// token continues the previous property's values unless it is a known key for
// this kind, or it looks like `unknown-key value` (a mistyped key, which the
// compiler should report as such rather than swallow as a list item).
func (p *parser) continuesList(kind string) bool {
	t, n := p.peek(), p.peekAt(1)
	if t.kind == tIdent && isKey(kind, t.text) {
		return false
	}
	if t.kind == tLBrack {
		return true
	}
	if t.kind == tNumber && n.kind == tIdent && p.peekAt(2).kind == tSlash {
		return true // a quantity, e.g. `rate 20k tokens/min, 100 requests/min`
	}
	switch n.kind {
	case tComma, tRBrace, tEOF:
		return t.kind == tIdent || t.kind == tString || t.kind == tNumber
	}
	return false
}

func (p *parser) parseProp(d *Decl) *Prop {
	kt := p.next()
	if kt.kind != tIdent {
		p.errorf(kt.pos, "", "expected a property name in %s %s, found %s", d.Kind, d.Name, kt.describe())
		return nil
	}
	prop := &Prop{Key: kt.text, Pos: kt.pos}
	for {
		switch p.peek().kind {
		case tComma, tRBrace, tEOF:
			if len(prop.Values) == 0 {
				p.errorf(kt.pos, "", "property %q in %s %s has no value", kt.text, d.Kind, d.Name)
			}
			return prop
		}
		prop.Values = append(prop.Values, p.parseValue())
	}
}

func (p *parser) parseValue() Value {
	t := p.next()
	switch t.kind {
	case tIdent:
		return Value{Kind: VIdent, Pos: t.pos, Text: t.text}
	case tString:
		return Value{Kind: VString, Pos: t.pos, Text: t.text}
	case tNumber:
		n, err := parseNumber(t.text)
		if err != nil {
			p.errorf(t.pos, "", "invalid number %q", t.text)
		}
		// Quantity: NUMBER IDENT '/' IDENT
		if p.peek().kind == tIdent && p.peekAt(1).kind == tSlash && p.peekAt(2).kind == tIdent {
			unit := p.next()
			p.next()
			per := p.next()
			return Value{Kind: VQuantity, Pos: t.pos, Num: n, Unit: unit.text, Per: per.text}
		}
		return Value{Kind: VNumber, Pos: t.pos, Num: n}
	case tLBrack:
		v := Value{Kind: VList, Pos: t.pos}
		for {
			switch p.peek().kind {
			case tRBrack:
				p.next()
				return v
			case tEOF, tRBrace:
				p.errorf(t.pos, "add a closing ']'", "list is never closed")
				return v
			case tComma:
				p.next()
				continue
			}
			v.Items = append(v.Items, p.parseValue())
		}
	}
	p.errorf(t.pos, "", "expected a value, found %s", t.describe())
	return Value{Kind: VIdent, Pos: t.pos}
}

func parseNumber(s string) (float64, error) {
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1_000, strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "m"):
		mult, s = 1_000_000, strings.TrimSuffix(s, "m")
	}
	n, err := strconv.ParseFloat(s, 64)
	return n * mult, err
}
