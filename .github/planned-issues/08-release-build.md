# Build and verify v0.2.0 distributions

Milestone: v0.2.0

## Problem
The next release needs installable artifacts and reproducible evidence.

## Acceptance criteria
Bump metadata; build wheel/sdist locally; install wheel from fresh local clone; run full checks/demo and document measured limitations.

## Test plan
Fresh clone uv sync, pytest, ruff, demo, corpus, benchmark, uv build and installed-wheel smoke tests.
