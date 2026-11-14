# ADR-0012: Supported MCP protocol versions

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Real servers run several protocol versions, and the oldest are often the most vulnerable.

## Decision

Test against protocol **2026-07-28 by default**, with **2025-11-25 behind a legacy flag**.

## Consequences

- ✅ Covers what builders run today.
- ⚠️ Two protocol paths in the harness.

## Alternatives considered

| Option | Why not |
|---|---|
| Latest only | Misses the servers most likely to be vulnerable. |

## Revisit when

A new protocol revision is published, or usage of the legacy version falls below a few percent.
