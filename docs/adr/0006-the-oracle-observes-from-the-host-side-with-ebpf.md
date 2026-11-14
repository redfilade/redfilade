# ADR-0006: The oracle observes from the host side with eBPF

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

A verdict is only as trustworthy as what it is based on. Anything running inside the cell may lie.

## Decision

The oracle combines **Tetragon** (eBPF process, file and network events), database snapshots, an egress sink and wire capture, all collected from outside the guest.

## Consequences

- ✅ Events are kernel-level and cannot be forged from inside the guest.
- ✅ Kubernetes-aware context for every event.
- ⚠️ Tetragon ties the oracle to Linux hosts with eBPF support.

## Alternatives considered

| Option | Why not |
|---|---|
| Falco | Rule-based detection; we need raw facts. |
| auditd | Lacks container context. |
| Target logs | Can be faked by the target. |

## Revisit when

Kata guest isolation hides events Tetragon needs.
