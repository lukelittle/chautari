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

// Package cdl implements the Chautari Definition Language: lexing, parsing,
// and compilation into an *estate.Estate. See docs/CDL.md for the grammar.
package cdl

import (
	"fmt"
	"strings"
	"unicode"
)

// Pos is a position in a source file.
type Pos struct {
	Line, Col int
}

func (p Pos) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Col) }

type tokenKind int

const (
	tEOF tokenKind = iota
	tIdent
	tString
	tNumber
	tLBrace
	tRBrace
	tLBrack
	tRBrack
	tComma
	tSlash
)

func (k tokenKind) String() string {
	return [...]string{"end of file", "identifier", "string", "number", "'{'", "'}'", "'['", "']'", "','", "'/'"}[k]
}

type token struct {
	kind tokenKind
	text string // identifier name, decoded string, or number literal
	pos  Pos
}

func (t token) describe() string {
	switch t.kind {
	case tIdent:
		return fmt.Sprintf("identifier %q", t.text)
	case tString:
		return fmt.Sprintf("string %q", t.text)
	case tNumber:
		return fmt.Sprintf("number %s", t.text)
	}
	return t.kind.String()
}

type lexer struct {
	src  []rune
	i    int
	line int
	col  int
	errs *ErrorList
	file string
}

func lex(file string, src string, errs *ErrorList) []token {
	l := &lexer{src: []rune(src), line: 1, col: 1, errs: errs, file: file}
	var toks []token
	for {
		t := l.next()
		toks = append(toks, t)
		if t.kind == tEOF {
			return toks
		}
	}
}

func (l *lexer) peek(off int) rune {
	if l.i+off < len(l.src) {
		return l.src[l.i+off]
	}
	return 0
}

func (l *lexer) advance() rune {
	r := l.src[l.i]
	l.i++
	if r == '\n' {
		l.line++
		l.col = 1
	} else {
		l.col++
	}
	return r
}

func (l *lexer) pos() Pos { return Pos{l.line, l.col} }

// Identifiers are ASCII. Names become registry keys, Kubernetes labels and
// gateway route names, and a Unicode identifier would let a homoglyph
// ("tеam" with a Cyrillic е) pass as a distinct name. Display names go in
// strings.
func isLetter(r rune) bool     { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
func isDigit(r rune) bool      { return r >= '0' && r <= '9' }
func isIdentStart(r rune) bool { return r == '_' || isLetter(r) }
func isIdentPart(r rune) bool  { return r == '_' || r == '-' || r == '.' || isLetter(r) || isDigit(r) }
func isNonASCIIWord(r rune) bool {
	return r > unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r))
}

// ValidName reports whether s is a valid CDL identifier and so a valid name
// for a declaration: ASCII, starting with a letter or '_', then letters,
// digits, '_', '.' or '-', not ending in '.' or '-', at most 63 characters.
// The API uses it to hold names created at run time to the same rule.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > MaxNameLen || !isIdentStart(rune(s[0])) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentPart(rune(s[i])) {
			return false
		}
	}
	return s[len(s)-1] != '.' && s[len(s)-1] != '-'
}

// MaxNameLen is the longest declaration name, the DNS label limit, since
// names end up in Kubernetes and gateway resource names.
const MaxNameLen = 63

func (l *lexer) next() token {
	l.skipSpaceAndComments()
	p := l.pos()
	if l.i >= len(l.src) {
		return token{kind: tEOF, pos: p}
	}
	r := l.peek(0)
	switch r {
	case '{':
		l.advance()
		return token{tLBrace, "{", p}
	case '}':
		l.advance()
		return token{tRBrace, "}", p}
	case '[':
		l.advance()
		return token{tLBrack, "[", p}
	case ']':
		l.advance()
		return token{tRBrack, "]", p}
	case ',':
		l.advance()
		return token{tComma, ",", p}
	case '/':
		l.advance()
		return token{tSlash, "/", p}
	case '"':
		return l.str(p)
	}
	if isDigit(r) {
		return l.number(p)
	}
	if isIdentStart(r) || isNonASCIIWord(r) {
		var b strings.Builder
		ascii := true
		for l.i < len(l.src) && (isIdentPart(l.peek(0)) || isNonASCIIWord(l.peek(0))) {
			ascii = ascii && isIdentPart(l.peek(0))
			b.WriteRune(l.advance())
		}
		if !ascii {
			l.errs.add(l.file, p, fmt.Sprintf("identifier %q contains non-ASCII characters", b.String()),
				"identifiers are ASCII; use a string for display names")
			return token{tIdent, b.String(), p}
		}
		// An identifier may not end in '.' or '-'; give them back.
		s := b.String()
		for len(s) > 1 && (s[len(s)-1] == '.' || s[len(s)-1] == '-') {
			s = s[:len(s)-1]
			l.i--
			l.col--
		}
		return token{tIdent, s, p}
	}
	l.advance()
	l.errs.add(l.file, p, fmt.Sprintf("unexpected character %q", r), "")
	return l.next()
}

func (l *lexer) skipSpaceAndComments() {
	for l.i < len(l.src) {
		r := l.peek(0)
		switch {
		case unicode.IsSpace(r):
			l.advance()
		case r == '#' || (r == '/' && l.peek(1) == '/'):
			for l.i < len(l.src) && l.peek(0) != '\n' {
				l.advance()
			}
		case r == '/' && l.peek(1) == '*':
			p := l.pos()
			l.advance()
			l.advance()
			closed := false
			for l.i < len(l.src) {
				if l.peek(0) == '*' && l.peek(1) == '/' {
					l.advance()
					l.advance()
					closed = true
					break
				}
				l.advance()
			}
			if !closed {
				l.errs.add(l.file, p, "unterminated block comment", "close it with */")
			}
		default:
			return
		}
	}
}

func (l *lexer) str(p Pos) token {
	l.advance() // opening quote
	var b strings.Builder
	for l.i < len(l.src) {
		r := l.advance()
		switch r {
		case '"':
			return token{tString, b.String(), p}
		case '\\':
			if l.i >= len(l.src) {
				break
			}
			e := l.advance()
			// Only \" and \\: strings may not contain control characters
			// (see checkString), so \n or \t could only produce an error.
			switch e {
			case '"', '\\':
				b.WriteRune(e)
			default:
				l.errs.add(l.file, p, fmt.Sprintf("unknown escape \\%c in string", e), `supported escapes are \" and \\; strings may not contain control characters`)
			}
		case '\n':
			l.errs.add(l.file, p, "unterminated string", "strings may not span lines")
			return token{tString, b.String(), p}
		default:
			b.WriteRune(r)
		}
	}
	l.errs.add(l.file, p, "unterminated string", "")
	return token{tString, b.String(), p}
}

func (l *lexer) number(p Pos) token {
	var b strings.Builder
	for l.i < len(l.src) && isDigit(l.peek(0)) {
		b.WriteRune(l.advance())
	}
	if l.peek(0) == '.' && isDigit(l.peek(1)) {
		b.WriteRune(l.advance())
		for l.i < len(l.src) && isDigit(l.peek(0)) {
			b.WriteRune(l.advance())
		}
	}
	// Magnitude suffix, only if not the start of a longer identifier.
	if s := l.peek(0); (s == 'k' || s == 'm' || s == 'K' || s == 'M') && !isIdentPart(l.peek(1)) && !isNonASCIIWord(l.peek(1)) {
		b.WriteRune(unicode.ToLower(l.advance()))
	}
	return token{tNumber, b.String(), p}
}
