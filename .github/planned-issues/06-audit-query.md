# Version audit JSONL and add query CLI

Milestone: v0.2.0

## Problem
Local logs lack a stable export contract and focused filtering.

## Acceptance criteria
Publish a JSON Schema; emit versioned payload-free records; query by decision/method/reason/time with bounded output and actionable line errors.

## Test plan
Schema, privacy, filtering, malformed-line and CLI tests against real files.
