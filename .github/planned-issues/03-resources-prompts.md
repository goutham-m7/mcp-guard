# Guard text resources and prompts

Milestone: v0.2.0

## Problem
Tools-only guards leave useful MCP read surfaces unavailable.

## Acceptance criteria
Namespaced prompt discovery/get and opaque resource URI discovery/read enforce policy, metadata pins and output scanning; binary content is denied.

## Test plan
Real subprocess journeys plus hostile metadata/output, invalid shape, pagination and changed metadata tests.
