# ADR-0001: Isolate attack runs in microVMs

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Every run executes code we expect to be exploited: Range targets, contributed attacks and builders' own servers. Whatever runs inside must not reach the host, other runs or our keys.

## Decision

Hosted and CI runs use **Kata Containers with Firecracker microVMs**. Laptop runs use **gVisor**. Plain Docker is supported only with a visible warning, and escape-class scenarios refuse to run on it (see 10.4 of the architecture record).

## Consequences

- ✅ Each run gets its own kernel: root inside the cell is not root on the host.
- ✅ microVMs boot in about a second, so per-run cells stay affordable.
- ⚠️ Firecracker needs bare-metal or nested-virtualisation hosts, which narrows cloud choice.
- ⚠️ Two isolation backends to maintain and test.

## Alternatives considered

| Option | Why not |
|---|---|
| Docker only | Shares the host kernel; one kernel bug away from escape. |
| Full VMs | Boot too slowly and cost too much per run. |

## Revisit when

Firecracker cannot run on the chosen cloud, or gVisor blocks a needed syscall class.
