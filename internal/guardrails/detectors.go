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

package guardrails

import (
	"math/big"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Span is a detected range in a text, with the detector that found it.
type Span struct {
	Detector string
	Start    int
	End      int
}

// detector finds spans in text.
type detector func(text string) []Span

var (
	reSSN = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	// reDigitRun finds runs of digit groups joined by single spaces or dashes;
	// detectCards looks for a card number inside each run.
	reDigitRun = regexp.MustCompile(`\b\d+(?:[ -]\d+)*\b`)
	// Local part and domain labels are Unicode-aware so that "jöhn@…" is
	// redacted whole, not just its ASCII tail.
	reEmail  = regexp.MustCompile(`(?i)[\p{L}\p{M}\p{N}._%+\-]+@[\p{L}\p{M}\p{N}.\-]+\.[\p{L}\p{M}]{2,}`)
	rePhone  = regexp.MustCompile(`(?:\+\d{1,3}[ .\-]?)?\(?\b\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}\b`)
	reIBAN   = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`)
	reAWSKey = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
)

func regexDetector(name string, re *regexp.Regexp, valid func(string) bool) detector {
	return func(text string) []Span {
		var out []Span
		for _, m := range re.FindAllStringIndex(text, -1) {
			if valid == nil || valid(text[m[0]:m[1]]) {
				out = append(out, Span{Detector: name, Start: m[0], End: m[1]})
			}
		}
		return out
	}
}

// validSSN rejects numbers the SSA never issues (area 000, 666, 9xx; group
// 00; serial 0000), which removes most false positives from dates and ids.
func validSSN(s string) bool {
	area, group, serial := s[0:3], s[4:6], s[7:11]
	return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// validCard applies the Luhn checksum.
func validCard(s string) bool {
	d := digits(s)
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// detectCards finds payment card numbers. A run of digit groups often
// carries more than the card ("4111 1111 1111 1111 123", "…1111 12/27"), so
// each run is searched for a Luhn-valid window of 13 to 19 digits that starts
// and ends on group boundaries and uses one kind of separator throughout,
// preferring the earliest start and then the longest window. Requiring whole
// groups and a uniform separator keeps dates, phone lists and other ids from
// being stitched into a number that passes Luhn by chance.
func detectCards(text string) []Span {
	var out []Span
	for _, m := range reDigitRun.FindAllStringIndex(text, -1) {
		run := text[m[0]:m[1]]
		// Group i is run[starts[i]:ends[i]]; separators sit between groups.
		var starts, ends []int
		for i := 0; i < len(run); {
			j := i
			for j < len(run) && run[j] >= '0' && run[j] <= '9' {
				j++
			}
			starts, ends = append(starts, i), append(ends, j)
			i = j + 1
		}
		for s := 0; s < len(starts); s++ {
			best, n := -1, 0
			for e := s; e < len(starts); e++ {
				if e > s && run[ends[e-1]] != run[ends[s]] {
					break // mixed separators
				}
				n += ends[e] - starts[e]
				if n > 19 {
					break
				}
				if n >= 13 && validCard(run[starts[s]:ends[e]]) {
					best = e
				}
			}
			if best >= 0 {
				out = append(out, Span{Detector: "card", Start: m[0] + starts[s], End: m[0] + ends[best]})
				s = best
			}
		}
	}
	return out
}

// validIBAN applies the ISO 13616 mod-97 check.
func validIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	re := s[4:] + s[:4]
	var b strings.Builder
	for _, r := range re {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteString(big.NewInt(int64(r - 'A' + 10)).String())
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

// detectIBANs finds IBANs in any letter case. The pattern is greedy and can
// swallow a following word ("BE68 5390 0754 7034 TODAY"), so when the whole
// match fails mod-97 we retry it cut back at each space, longest first, down
// to the 15-character minimum. Cuts happen only at spaces: trimming single
// characters would give each match many more chances to pass mod-97 (a 1 in
// 97 check) by accident.
func detectIBANs(text string) []Span {
	var out []Span
	for pos := 0; pos < len(text); {
		m := reIBAN.FindStringIndex(text[pos:])
		if m == nil {
			break
		}
		start, end := pos+m[0], pos+m[1]
		pos = end
		for e := end; e > start; e = strings.LastIndexByte(text[start:e], ' ') + start {
			if validIBAN(text[start:e]) {
				out = append(out, Span{Detector: "iban", Start: start, End: e})
				pos = e
				break
			}
		}
	}
	return out
}

// PII detectors by name.
var piiDetectors = map[string]detector{
	"ssn":     regexDetector("ssn", reSSN, validSSN),
	"card":    detectCards,
	"email":   regexDetector("email", reEmail, nil),
	"phone":   regexDetector("phone", rePhone, nil),
	"iban":    detectIBANs,
	"aws-key": regexDetector("aws-key", reAWSKey, nil),
}

// injectionPattern is one signal of a prompt-injection attempt.
type injectionPattern struct {
	re     *regexp.Regexp
	weight float64
}

// Weights are tuned so that one strong signal, or two weak ones, trips the
// threshold of 1.0. This is a heuristic first line; pair it with a model-based
// guardrail (Bedrock) for adversarial traffic.
var injectionPatterns = []injectionPattern{
	{regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|guidelines|directives)\b`), 1.0},
	{regexp.MustCompile(`(?i)\b(reveal|print|show|repeat|output|leak)\b[^.\n]{0,30}\b(system prompt|hidden (prompt|instructions)|initial instructions)\b`), 1.0},
	{regexp.MustCompile(`(?i)\b(do anything now|DAN mode|developer mode|jailbreak(ed)?)\b`), 1.0},
	{regexp.MustCompile(`(?i)\byou are (now|no longer)\b[^.\n]{0,40}\b(unrestricted|unfiltered|without (any )?(rules|restrictions|limits)|not bound)\b`), 1.0},
	{regexp.MustCompile(`(?im)<\|im_(start|end)\|>|\[/?INST\]|<<SYS>>|^\s*#{2,}\s*system\b`), 1.0},
	{regexp.MustCompile(`(?i)\bpretend\b[^.\n]{0,30}\b(no|without)\b[^.\n]{0,20}\b(restrictions|rules|filters|guardrails)\b`), 0.8},
	{regexp.MustCompile(`(?i)\b(new|updated) instructions?\s*:`), 0.5},
	{regexp.MustCompile(`(?i)\bact as\b[^.\n]{0,30}\b(admin|root|system|developer)\b`), 0.5},
	{regexp.MustCompile(`(?i)\bbase64\b[^.\n]{0,30}\b(decode|execute|follow)\b`), 0.5},
}

// detectInjection scores the text; above threshold, every matched span is
// reported.
func detectInjection(text string) []Span {
	var spans []Span
	score := 0.0
	for _, p := range injectionPatterns {
		for _, m := range p.re.FindAllStringIndex(text, -1) {
			spans = append(spans, Span{Detector: "injection", Start: m[0], End: m[1]})
			score += p.weight
		}
	}
	if score < 1.0 {
		return nil
	}
	return spans
}

// topicDetector matches blocked-topic phrases as whole words, ignoring case
// and runs of whitespace. RE2's \b only knows ASCII word characters, so it
// cannot bound "café", Devanagari, "401(k)" or "C++". Instead a boundary is
// required only at an edge whose rune is itself a word character (letter,
// combining mark, digit or underscore), and the topic is captured so the
// span excludes the boundary character.
func topicDetector(topics []string) detector {
	const word = `\p{L}\p{M}\p{N}_`
	isWord := func(r rune) bool {
		return r == '_' || unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r)
	}
	var res []*regexp.Regexp
	for _, t := range topics {
		words := strings.Fields(t)
		if len(words) == 0 {
			continue
		}
		for i, w := range words {
			words[i] = regexp.QuoteMeta(w)
		}
		pre, post := "", ""
		if first, _ := utf8.DecodeRuneInString(words[0]); isWord(first) {
			pre = `(?:^|[^` + word + `])`
		}
		if last, _ := utf8.DecodeLastRuneInString(words[len(words)-1]); isWord(last) {
			post = `(?:$|[^` + word + `])`
		}
		res = append(res, regexp.MustCompile(`(?i)`+pre+`(`+strings.Join(words, `[\s\p{Z}]+`)+`)`+post))
	}
	return func(text string) []Span {
		var out []Span
		for _, re := range res {
			// The boundaries consume a character, so resume each search at the
			// end of the topic itself, not of the whole match, or "tip tip"
			// would find only one. Resuming there is sound: the character
			// before the resume point is the topic's own last rune.
			for pos := 0; pos < len(text); {
				m := re.FindStringSubmatchIndex(text[pos:])
				if m == nil {
					break
				}
				out = append(out, Span{Detector: "topic", Start: pos + m[2], End: pos + m[3]})
				pos += m[3]
			}
		}
		return out
	}
}

// redact replaces spans with [REDACTED:DETECTOR] markers, merging overlaps.
func redact(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	var b strings.Builder
	pos := 0
	for i := 0; i < len(spans); i++ {
		s := spans[i]
		end := s.End
		for i+1 < len(spans) && spans[i+1].Start < end {
			i++
			if spans[i].End > end {
				end = spans[i].End
			}
		}
		if s.Start < pos {
			continue
		}
		b.WriteString(text[pos:s.Start])
		b.WriteString("[REDACTED:" + strings.ToUpper(s.Detector) + "]")
		pos = end
	}
	b.WriteString(text[pos:])
	return b.String()
}
