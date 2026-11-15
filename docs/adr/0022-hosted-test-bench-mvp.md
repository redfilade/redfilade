# ADR-0022: Hosted Test Bench, first version

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Phase 3 ends with a hosted Test Bench: organisations verify their domains and have Redfilade test their remote MCP servers. The architecture record plans for OAuth sign-in (ADR-0009), Postgres (ADR-0004, ADR-0005), microVM cells (ADR-0001) and Kubernetes (ADR-0002). Remote tests need no cell, since the target runs on the customer's own infrastructure, so a first version can ship without the cell platform.

## Decision

- **One Go binary, `redfilade-bench`:** `migrate`, `create-org` and `serve` (API plus workers). It refuses to serve on a non-loopback address without TLS.
- **Database:**
  - Migration `0002_bench.sql` adds API keys (SHA-256 hashes only), per-org domains, run fields and write-once evidence stored as exact text with a database-checked SHA-256.
  - Every table has row-level security enabled and forced.
  - Two narrow `SECURITY DEFINER` functions cross tenants: API-key lookup, and claiming the next queued run (`FOR UPDATE SKIP LOCKED`).
  - The app connects as a login role in `redfilade_app`, without BYPASSRLS, and sets the org in every transaction.
- **Driver:** our own small PostgreSQL client (`internal/pg`): extended query protocol only, SCRAM-SHA-256 with server-signature verification, optional TLS (default `verify-full` off-loopback). No dependency was added.
- **Authentication:** org API keys (`rfk_…`, shown once) with roles admin, tester and viewer. OAuth and SSO (ADR-0009) come later.
- **Remote tests:**
  - only `https` URLs on domains the org has verified;
  - never IP literals or localhost;
  - only public addresses, pinned for the run;
  - ownership and address are re-checked by the worker at run time;
  - remote-safe L1 and L2 attacks only;
  - at most 5 runs in flight per org.
- **Target tokens** a customer supplies for their own server are held in the API process's memory until the run finishes, and never stored.
- **Everything audited:** org and key creation, domain challenge and verification, run creation and completion.

## Consequences

- ✅ A working hosted service for remote testing, with tenant isolation enforced by the database, tested end to end against real PostgreSQL in CI.
- ✅ No new third-party code in the trust boundary.
- ⚠️ Our own Postgres client is security-relevant code to maintain; it supports only what the Bench needs (text format, no COPY or LISTEN).
- ⚠️ Target tokens are lost if the process restarts before a queued run starts; the run then proceeds without one.
- ⚠️ API keys instead of OAuth/SSO; evidence in Postgres rather than object storage. Both are planned replacements.
- ⚠️ Range scenarios (cells) are not offered as a hosted service yet: that needs the microVM platform (ADR-0001, ADR-0002).

## Alternatives considered

| Option | Why not |
|---|---|
| pgx driver | Well maintained, but a large dependency in the trust boundary, and it could not be fetched or tested in this build environment |
| Store target tokens encrypted | A key-management problem for a convenience; memory-only is simpler and safer for now |
| Allow IP-address targets | Ownership of an address cannot be proven like a domain |

## Revisit when

OAuth sign-in is built, a customer needs queued runs to survive restarts with credentials, or hosted Range runs need cells.
