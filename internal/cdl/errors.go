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
	"sort"
	"strings"
)

// Error is a single diagnostic with a source position and an optional hint.
type Error struct {
	File string
	Pos  Pos
	Msg  string
	Hint string
}

func (e Error) Error() string {
	s := fmt.Sprintf("%s:%s: %s", e.File, e.Pos, e.Msg)
	if e.Hint != "" {
		s += "\n    " + e.Hint
	}
	return s
}

// ErrorList collects every diagnostic so users see them all at once.
type ErrorList []Error

func (l *ErrorList) add(file string, p Pos, msg, hint string) {
	*l = append(*l, Error{File: file, Pos: p, Msg: msg, Hint: hint})
}

func (l ErrorList) Error() string {
	sorted := append(ErrorList(nil), l...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Pos.Line != sorted[j].Pos.Line {
			return sorted[i].Pos.Line < sorted[j].Pos.Line
		}
		return sorted[i].Pos.Col < sorted[j].Pos.Col
	})
	parts := make([]string, len(sorted))
	for i, e := range sorted {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n")
}

func (l ErrorList) err() error {
	if len(l) == 0 {
		return nil
	}
	return l
}

// suggest returns a "did you mean" hint for the closest candidate, if any is
// close enough to be a plausible typo.
func suggest(got string, candidates []string) string {
	best, bestD := "", 1<<30
	for _, c := range candidates {
		if d := levenshtein(got, c); d < bestD {
			best, bestD = c, d
		}
	}
	limit := len(got) / 3
	if limit < 2 {
		limit = 2
	}
	if best != "" && bestD <= limit {
		return fmt.Sprintf("did you mean %q?", best)
	}
	if len(candidates) > 0 && len(candidates) <= 8 {
		q := make([]string, len(candidates))
		for i, c := range candidates {
			q[i] = fmt.Sprintf("%q", c)
		}
		return "expected one of " + strings.Join(q, ", ")
	}
	return ""
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
