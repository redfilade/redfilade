# ADR-0004: Postgres for results, write-once object storage for evidence

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Results need schemas and strict tenant isolation. Evidence must be impossible to edit after the fact.

## Decision

**Postgres** for metadata and results, with row-level security forced on every tenant table (`db/migrations/0001_tenancy.sql`). **S3-compatible object storage with Object Lock** for evidence bundles.

## Consequences

- ✅ The database enforces tenant isolation, not just the application.
- ✅ Evidence is write-once.
- ⚠️ Object Lock retention needs careful configuration to respect deletion requests.

## Alternatives considered

| Option | Why not |
|---|---|
| MongoDB | Does not enforce the schemas we rely on. |
| Evidence in the database | Too easy to edit. |

## Revisit when

Evidence volume makes Object Lock costs significant.
