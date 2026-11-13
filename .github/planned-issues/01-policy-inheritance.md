# Conjunctive server policy inheritance

Milestone: v0.2.0

## Problem
Repeated per-tool restrictions drift between servers.

## Acceptance criteria
Matching server rules constrain matching tool/resource/prompt grants; deny wins; server rates share a bucket across operations.

## Test plan
Unit tests for narrowing, deny, shared rate windows and default denial.
