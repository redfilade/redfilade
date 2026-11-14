# ADR-0010: Remote testing only against verified domains

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

The hosted Test Bench sends attacks to a URL. Without proof of ownership, Redfilade would become a free attack service.

## Decision

Remote tests are allowed **only to verified domains** (DNS TXT record or `/.well-known/` token), enforced with FQDN-aware network policy (for example Cilium). Every remote test is logged with the requesting account.

## Consequences

- ✅ Stops scanning of sites the user does not own.
- ✅ Clear audit trail.
- ⚠️ Builders must complete verification before their first remote test.

## Alternatives considered

| Option | Why not |
|---|---|
| Open egress | Turns the range into an attack service against third parties. |
| Any URL the user types | Same problem with an extra step. |

## Revisit when

A safer ownership proof becomes standard.
