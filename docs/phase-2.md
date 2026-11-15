# Phase 2: the real Range

> The L2 battery, signed scenario packs with a consent gate, and a triage lane for contributed attacks. Done when every L2 vulnerable twin is exploited and every secure twin holds in CI, packs are refused or accepted by policy, and a contributed scenario can be triaged without running contributor code.

## Checklist

| Item | Where | Status |
|---|---|---|
| Egress sink: per-run internal network, request log, sink canary | `infra/sink`, `internal/sandbox` | ✅ |
| Oracle facts: `secret_pattern_leaked`, `sensitive_file_read`, `egress_reached_sink`, `canary_egressed` | `internal/oracle` | ✅ |
| L2 battery: path traversal, SSRF, secrets in output (L2 includes L1) | `internal/battery/l2.go` | ✅ |
| L2 twins and scenarios | `targets/{path-traversal,ssrf,secrets-in-output}`, `scenarios/l2-*` | ✅ |
| SARIF rules for the new facts | `internal/report` | ✅ |
| Built-in scenarios embedded and run by id | `scenarios/embed.go` | ✅ |
| Pack digest, signature check and policy (ADR-0016) | `internal/pack` | ✅ |
| Consent screen shows source and signature | `internal/consent` | ✅ |
| CLI: `scenario list`, `scenario validate`, `pack digest`, `pack verify`, policy flags | `cmd/redfilade` | ✅ |
| Release signs every scenario as a pack and verifies it with the CLI | `release.yml` → `range-proof` | ⬜ runs with the Phase 1 dry run (needs the `release` environment) |
| Triage lane for contributed scenarios | `triage.yml`, `redfilade triage summarize` | ✅ needs the `triage` label created (below) |

## Maintainer steps

1. Create a label named `triage` (Issues → Labels). Only people with triage rights or above can apply labels, so only maintainers can start the lane.
2. After merging this phase, run the release workflow dry run from Phase 0 step E. It now also produces the `scenario-packs-*` artifact; download one and run `redfilade pack verify DIR` locally to see a verified pack.

## What is honest about this phase

- Token audience and rate-limit checks from the L2 list need the HTTP transport, which comes with Phase 3. Command and SQL injection twins are not built yet.
- The cell is still a hardened container, not a microVM (ADR-0001).
- File reads and process execution inside the cell are still not observed directly; `sensitive_file_read` is detected from what the target returns.
- Triage cannot run a contribution that needs a new twin until that twin is reviewed and merged.
