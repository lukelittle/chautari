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

// Package guardrails inspects prompts and completions against the policies
// an estate declares, and redacts, blocks or flags what they find.
//
// Detection is pluggable: PII, prompt injection and blocked topics are built
// in; Amazon Bedrock Guardrails is an adapter behind a narrow interface. A
// detector that errors blocks the request. We fail closed.
package guardrails

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/lukelittle/chautari/internal/estate"
)

// Finding summarises what one detector found under one policy. Counts and
// names only: raw matches never leave this package, so they never reach the
// audit log.
type Finding struct {
	Policy   string        `json:"policy"`
	Detector string        `json:"detector"`
	Action   estate.Action `json:"action"`
	Count    int           `json:"count"`
}

// Outcome is the result of inspecting a set of texts in one direction.
type Outcome struct {
	// Texts are the inputs, with redactions applied.
	Texts    []string  `json:"-"`
	Blocked  bool      `json:"blocked"`
	Reason   string    `json:"reason,omitempty"`
	Findings []Finding `json:"findings"`
}

// Strongest returns the strongest action taken, or "" if nothing fired.
func (o Outcome) Strongest() estate.Action {
	var best estate.Action
	for _, f := range o.Findings {
		if f.Action.Strength() > best.Strength() {
			best = f.Action
		}
	}
	return best
}

// Redacted reports whether any text was changed.
func (o Outcome) Redacted() bool {
	for _, f := range o.Findings {
		if f.Action == estate.Redact {
			return true
		}
	}
	return false
}

// BedrockClient is the slice of Bedrock runtime Chautari needs.
type BedrockClient interface {
	ApplyGuardrail(ctx context.Context, id, version string, dir estate.Direction, texts []string) (BedrockResult, error)
}

// BedrockResult is Bedrock's verdict. Outputs, when present, are Bedrock's
// masked versions of the inputs.
type BedrockResult struct {
	Intervened bool
	Outputs    []string
	Reasons    []string
}

// Engine applies an estate's policies.
type Engine struct {
	policies []estate.Policy
	bedrock  BedrockClient
}

// New returns an engine for the estate's policies. bedrock may be nil if no
// policy names a Bedrock guardrail.
func New(e *estate.Estate, bedrock BedrockClient) (*Engine, error) {
	for _, p := range e.Policies {
		if p.BedrockGuardrail != "" && bedrock == nil {
			return nil, fmt.Errorf("policy %s uses Bedrock guardrail %s but no Bedrock client is configured", p.Name, p.BedrockGuardrail)
		}
	}
	return &Engine{policies: e.Policies, bedrock: bedrock}, nil
}

// HasDirection reports whether any policy for the team inspects dir. The
// checkpoint uses this to decide whether a streamed response can be passed
// straight through or must be buffered and checked first.
func (g *Engine) HasDirection(team string, dir estate.Direction) bool {
	for _, p := range g.policies {
		if !p.AppliesToTeam(team) {
			continue
		}
		for _, r := range p.Rules {
			if r.Direction == dir {
				return true
			}
		}
	}
	return false
}

// Inspect runs every policy that applies to team in direction dir over texts.
func (g *Engine) Inspect(ctx context.Context, team string, dir estate.Direction, texts []string) (Outcome, error) {
	out := Outcome{Texts: append([]string(nil), texts...), Findings: []Finding{}}
	redactions := make([][]Span, len(texts))

	for _, p := range g.policies {
		if !p.AppliesToTeam(team) {
			continue
		}
		// detector -> strongest action for this policy and direction
		want := map[string]estate.Action{}
		for _, r := range p.Rules {
			if r.Direction != dir {
				continue
			}
			for _, d := range r.Detectors {
				if r.Action.Strength() > want[d].Strength() {
					want[d] = r.Action
				}
			}
		}
		if len(want) == 0 {
			continue
		}
		dets := make([]string, 0, len(want))
		for d := range want {
			dets = append(dets, d)
		}
		sort.Strings(dets)

		for _, name := range dets {
			action := want[name]
			if name == "bedrock" {
				// Spans are byte offsets into the current texts, and Bedrock may
				// replace them with masked text of a different length. Apply what
				// is pending first, so Bedrock sees (and masks) redacted text and
				// every later span is computed on the text it will be applied to.
				for i := range out.Texts {
					out.Texts[i] = redact(out.Texts[i], redactions[i])
					redactions[i] = nil
				}
				if err := g.applyBedrock(ctx, p, dir, action, &out); err != nil {
					return blocked(out, fmt.Sprintf("guardrail %s/bedrock failed: %v", p.Name, err)), nil
				}
				if out.Blocked {
					return out, nil
				}
				continue
			}
			det := g.detector(p, name)
			if det == nil {
				return blocked(out, fmt.Sprintf("guardrail %s: unknown detector %s", p.Name, name)), nil
			}
			count := 0
			for i, t := range out.Texts {
				spans := det(t)
				count += len(spans)
				if action == estate.Redact {
					redactions[i] = append(redactions[i], spans...)
				}
			}
			if count == 0 {
				continue
			}
			out.Findings = append(out.Findings, Finding{Policy: p.Name, Detector: name, Action: action, Count: count})
			if action == estate.Block {
				return blocked(out, fmt.Sprintf("blocked by policy %s: %s detected in %s text", p.Name, name, dir)), nil
			}
		}
	}
	for i := range out.Texts {
		out.Texts[i] = redact(out.Texts[i], redactions[i])
	}
	return out, nil
}

func blocked(o Outcome, reason string) Outcome {
	o.Blocked = true
	o.Reason = reason
	o.Texts = nil
	return o
}

func (g *Engine) detector(p estate.Policy, name string) detector {
	switch name {
	case "injection":
		return detectInjection
	case "topic":
		return topicDetector(p.Topics)
	}
	return piiDetectors[name]
}

func (g *Engine) applyBedrock(ctx context.Context, p estate.Policy, dir estate.Direction, action estate.Action, out *Outcome) error {
	if g.bedrock == nil {
		return fmt.Errorf("no Bedrock client")
	}
	res, err := g.bedrock.ApplyGuardrail(ctx, p.BedrockGuardrail, p.BedrockVersion, dir, out.Texts)
	if err != nil {
		return err
	}
	if !res.Intervened {
		return nil
	}
	out.Findings = append(out.Findings, Finding{Policy: p.Name, Detector: "bedrock", Action: action, Count: 1})
	switch action {
	case estate.Block:
		reason := "blocked by policy " + p.Name + ": Bedrock guardrail intervened"
		if len(res.Reasons) > 0 {
			reason += " (" + strings.Join(res.Reasons, ", ") + ")"
		}
		*out = blocked(*out, reason)
	case estate.Redact:
		if len(res.Outputs) == len(out.Texts) {
			copy(out.Texts, res.Outputs)
		} else {
			*out = blocked(*out, "blocked by policy "+p.Name+": Bedrock intervened without masked output")
		}
	}
	return nil
}

// Detect runs a single built-in detector, for the admin UI's policy tester.
func Detect(name, text string, topics []string) ([]Span, error) {
	switch name {
	case "injection":
		return detectInjection(text), nil
	case "topic":
		return topicDetector(topics)(text), nil
	}
	d, ok := piiDetectors[name]
	if !ok {
		return nil, fmt.Errorf("unknown detector %q", name)
	}
	return d(text), nil
}
