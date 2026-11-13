# Offline policy lint command

Milestone: v0.2.0

## Problem
Configuration errors currently surface only when a proxy starts.

## Acceptance criteria
policy check validates YAML without starting upstreams; JSON diagnostics distinguish errors and warnings; strict mode rejects broad grants.

## Test plan
CLI tests for valid, malformed, duplicate, broad and contradictory rules.
