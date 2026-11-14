# ADR-0008: A thin, fully reviewable model proxy

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

L3 runs need AI models. Provider keys are the most valuable secret in the system and the first thing an exploited run would look for.

## Decision

Build **our own thin model proxy**. Keys never leave it; each run gets a short-lived per-run token with a hard budget.

## Consequences

- ✅ Small enough to review completely.
- ✅ Spend caps per tenant.
- ⚠️ We maintain provider integrations ourselves.

## Alternatives considered

| Option | Why not |
|---|---|
| Keys in the harness | Stolen by the first exploit. |
| A general LLM gateway product | Large attack surface around the key. |

## Revisit when

A maintained gateway offers the same small, auditable core.
