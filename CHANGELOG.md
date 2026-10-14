# Changelog

## 0.1.0 (unreleased)

First release.

- **CDL**: the Chautari Definition Language, with a compiler that reports every
  error with its position and a suggested fix.
- **`chautari generate`**: renders agentgateway config, Docker Compose, a Helm
  chart, AWS Terraform, OpenTelemetry config, the Rego bundle and a controls
  report. Generation is idempotent and leaves files you edited alone.
- **Checkpoint** for OpenAI-compatible chat completions (including streaming),
  MCP and A2A: OPA policy, guardrails, budgets, rate limits and audit.
- **Registry** with a separation-of-duties approval workflow and a kill switch.
- **Guardrails**:
  - PII (SSN, card, email, phone, IBAN, AWS keys)
  - prompt injection
  - blocked topics
  - Amazon Bedrock Guardrails
- **Audit log**: append-only and hash-chained, with offline verification.
- **Controls report**: maps Chautari's controls to NIST AI RMF 1.0 and SR 11-7.
- **Admin UI**.
- **Demo**: an offline demo with a mock provider and a traffic generator.
