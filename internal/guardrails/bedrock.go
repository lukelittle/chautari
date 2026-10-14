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
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"

	"github.com/lukelittle/chautari/internal/estate"
)

// applyGuardrailAPI is the one SDK call we use, so tests can fake it.
type applyGuardrailAPI interface {
	ApplyGuardrail(ctx context.Context, in *bedrockruntime.ApplyGuardrailInput, opts ...func(*bedrockruntime.Options)) (*bedrockruntime.ApplyGuardrailOutput, error)
}

// Bedrock adapts Amazon Bedrock's ApplyGuardrail API.
type Bedrock struct {
	api applyGuardrailAPI
}

// NewBedrock loads AWS configuration the standard way (env, profile, task
// role) for the given region.
func NewBedrock(ctx context.Context, region string) (*Bedrock, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return &Bedrock{api: bedrockruntime.NewFromConfig(cfg)}, nil
}

// ApplyGuardrail sends texts to a Bedrock guardrail.
func (b *Bedrock) ApplyGuardrail(ctx context.Context, id, version string, dir estate.Direction, texts []string) (BedrockResult, error) {
	source := types.GuardrailContentSourceInput
	if dir == estate.Outbound {
		source = types.GuardrailContentSourceOutput
	}
	content := make([]types.GuardrailContentBlock, len(texts))
	for i, t := range texts {
		content[i] = &types.GuardrailContentBlockMemberText{Value: types.GuardrailTextBlock{Text: aws.String(t)}}
	}
	if version == "" {
		version = "DRAFT"
	}
	out, err := b.api.ApplyGuardrail(ctx, &bedrockruntime.ApplyGuardrailInput{
		GuardrailIdentifier: aws.String(id),
		GuardrailVersion:    aws.String(version),
		Source:              source,
		Content:             content,
	})
	if err != nil {
		return BedrockResult{}, err
	}
	res := BedrockResult{Intervened: out.Action == types.GuardrailActionGuardrailIntervened}
	if res.Intervened && len(out.Outputs) == len(texts) {
		for _, o := range out.Outputs {
			res.Outputs = append(res.Outputs, aws.ToString(o.Text))
		}
	}
	for _, a := range out.Assessments {
		if a.ContentPolicy != nil && len(a.ContentPolicy.Filters) > 0 {
			res.Reasons = append(res.Reasons, "content policy")
		}
		if a.TopicPolicy != nil && len(a.TopicPolicy.Topics) > 0 {
			res.Reasons = append(res.Reasons, "denied topic")
		}
		if a.SensitiveInformationPolicy != nil && (len(a.SensitiveInformationPolicy.PiiEntities) > 0 || len(a.SensitiveInformationPolicy.Regexes) > 0) {
			res.Reasons = append(res.Reasons, "sensitive information")
		}
		if a.WordPolicy != nil && (len(a.WordPolicy.CustomWords) > 0 || len(a.WordPolicy.ManagedWordLists) > 0) {
			res.Reasons = append(res.Reasons, "word policy")
		}
	}
	return res, nil
}
