# ADR-0003: Languages: Go core, Python harness, TypeScript web

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

The hardened core, the attack harness and the web UI have different needs and different contributor pools.

## Decision

**Go** for the control plane, runner and CLI. **Python** for the attack harness and scenario SDK. **TypeScript** for the web UI and TypeScript targets.

## Consequences

- ✅ Go gives single static binaries and strong Kubernetes libraries.
- ✅ Python is the language of the official MCP SDK and of most security researchers.
- ✅ TypeScript covers half the MCP ecosystem.
- ⚠️ Three toolchains, three dependency policies (pnpm, uv, Go modules) to keep strict.

## Alternatives considered

| Option | Why not |
|---|---|
| Rust | Safer still, but a smaller contributor pool for this audience. |
| All Python | Puts an interpreter and its package tree in the hardened core. |

## Revisit when

Contributor demographics shift, or a single language covers two of the three roles well.
