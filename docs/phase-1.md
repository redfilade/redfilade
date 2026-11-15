# Phase 1: walking skeleton

> `redfilade test --server "..." --level L1` runs one battery attack against a vulnerable and secure twin, the oracle observes it, and a signed report comes out, also as SARIF from the CI action. Done when the secure twin passes, the vulnerable twin fails, and the signature verifies.

## Checklist

| Item | Where | Status |
|---|---|---|
| MCP client for 2026-07-28 (`server/discover`, `_meta`) and the 2025-11-25 handshake, hardened against hostile servers | `internal/mcp` | ✅ |
| Scenario format: data-only exploits, strict validation (ADR-0013) | `internal/scenario` | ✅ |
| Synthetic organisation with fresh random canaries per run (ADR-0014) | `internal/world` | ✅ |
| Hardened container cells, gVisor detection, consent gate (ADR-0015) | `internal/sandbox`, `internal/consent` | ✅ |
| Oracle that judges observed facts and lists what it cannot see | `internal/oracle` | ✅ |
| Evidence bundle, SARIF 2.1.0, JUnit, with hostile text escaped and canaries redacted | `internal/report` | ✅ |
| First battery attack: L1 leaky errors | `internal/battery` | ✅ |
| Vulnerable and secure twins (`FROM scratch`, no base image) | `targets/leaky-errors`, `scenarios/l1-leaky-errors` | ✅ |
| CLI: `scenario validate`, `range run`, `range gate`, `test` | `cmd/redfilade` | ✅ |
| CI: range gate and builder test in real cells | `ci.yml` → `range-gate` | ✅ runs on every PR |
| GitHub Action for builders, writing SARIF | `action.yml`, `ci.yml` → `action-selftest` | ✅ runs on every PR |
| Signed evidence that verifies | `release.yml` → `range-proof` | ⬜ needs the `release` environment and a maintainer-approved dry run (Phase 0 steps B and E) |

## What is honest about this phase

- The cell is a hardened container, not yet a microVM (ADR-0001). Reports say which tier ran.
- File reads and process execution inside the cell are not observed yet; every report lists this.
- Scenarios that declare the egress sink still run with no network until the sink exists.
