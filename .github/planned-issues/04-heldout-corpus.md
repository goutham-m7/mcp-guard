# Freeze an independent synthetic holdout

Milestone: v0.2.0

## Problem
The existing corpus was authored alongside detector rules.

## Acceptance criteria
Keep original tuning fixtures separate; freeze new held-out attack fixtures before evaluation and report misses without tuning detectors.

## Test plan
Assert disjoint IDs and payloads; replay all held-out cases through real subprocesses.
