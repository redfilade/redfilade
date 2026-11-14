# ADR-0002: Schedule runs and isolate tenants with Kubernetes

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Runs must be scheduled, given quotas, and kept apart per tenant. Enterprises must be able to run the same platform themselves.

## Decision

Use **Kubernetes**: runtime classes for Kata, namespaces per tenant, network policies and resource quotas. Self-hosting ships as a Helm chart.

## Consequences

- ✅ Isolation primitives are built in and widely reviewed.
- ✅ Enterprises already operate Kubernetes.
- ⚠️ Operational complexity for the hosted service.
- ⚠️ The cluster itself becomes high-value attack surface.

## Alternatives considered

| Option | Why not |
|---|---|
| Nomad | Smaller policy and network-isolation ecosystem. |
| Custom VM manager | Reinvents isolation we would then have to defend alone. |

## Revisit when

A managed alternative offers equal isolation with less to operate.
