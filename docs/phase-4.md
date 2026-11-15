# Phase 4: clients and defences

> L4 tests MCP clients and hosts against a hostile server; L5 measures gateways and guardrails against every scenario and a benign task set.

## Checklist

| Item | Where | Status |
|---|---|---|
| 4a. Hostile server with hidden-instruction, elicitation and sampling probes | `internal/hostile` | ✅ |
| 4a. L4 facts and SARIF rules | `internal/oracle`, `internal/report` | ✅ |
| 4a. Client scenario kind, client twins and `l4-hostile-server` in the gate | `scenarios/l4-hostile-server`, `targets/mcp-client` | ✅ |
| 4a. `redfilade hostile-server` and `client-report` for your own client | `cmd/redfilade` | ✅ |
| 4b. L5 defence measurement | | ⬜ |

## What is honest about this phase so far

- Redfilade judges what a client sends, not what it shows: an answer the user approved looks like an automatic one.
- Server-initiated requests use the 2025-11-25 form; the 2026-07-28 multi-round-trip form comes later.
