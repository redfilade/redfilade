# ADR-0005: Postgres job table before any message broker

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Jobs must move from the API to runners durably. Every extra component is something else to secure and operate.

## Decision

Use a **Postgres job table** (`SELECT ... FOR UPDATE SKIP LOCKED`) in v1. Move to **NATS JetStream** only when measured load requires it.

## Consequences

- ✅ One fewer component to secure.
- ✅ Handles thousands of runs a day.
- ⚠️ A migration later if load grows a lot.

## Alternatives considered

| Option | Why not |
|---|---|
| Kafka | Heavy for this scale. |
| Redis | Not durable by default. |

## Revisit when

Queue latency or lock contention exceeds the SLO under real load.
