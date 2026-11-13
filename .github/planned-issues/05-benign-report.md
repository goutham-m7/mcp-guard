# Expand benign coverage and report detector false positives

Milestone: v0.2.0

## Problem
Eleven benign fixtures underrepresent ordinary technical text.

## Acceptance criteria
Add diverse benign fixtures including quoted security text and public contacts; report each detector hit count and false-positive denominator.

## Test plan
Replay benign fixtures; verify per-detector counts and empty split summaries.
