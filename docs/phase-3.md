# Phase 3: hosted Test Bench

> Domain verification, remote targets and L3 agent-in-the-loop testing, then the hosted service that runs them. Done when a builder can verify a domain, test a remote MCP server safely, run an L3 agent scenario, and do both through the hosted Test Bench.

## Checklist

| Item | Where | Status |
|---|---|---|
| 3a. Streamable HTTP transport (2026-07-28 headers, SSE, legacy sessions, no redirects) | `internal/mcp/http.go` | ✅ |
| 3a. HTTP checks: token audience, rate limits, routing-header mismatch | `internal/battery/http.go`, `internal/oracle` | ✅ |
| 3a. `redfilade test --url` for servers on this machine | `cmd/redfilade` | ✅ |
| 3a. HTTP twin (vulnerable and secure) with an end-to-end test | `targets/http-auth`, `cmd/redfilade/remote_test.go` | ✅ |
| 3b. Domain verification (DNS TXT or HTTPS file), live re-check, public-address pinning, `redfilade domain` | `internal/domain`, `cmd/redfilade` | ✅ |
| 3b. `test --url` for verified HTTPS domains, with end-to-end tests | `cmd/redfilade/domain_test.go` | ✅ |
| 3c. L3 agent scenarios: agent loop, trials with a 95% interval, `agent_leaked_canary` | `internal/agent`, `internal/run` | ✅ |
| 3c. Models: scripted stand-ins for CI, Anthropic Messages API for real runs | `internal/agent/models.go` | ✅ |
| 3c. First L3 scenario and twins: inbox injection | `scenarios/l3-inbox-injection`, `targets/inbox-injection` | ✅ in the gate |
| 3d. Hosted Test Bench service | | ⬜ |

## What is honest about this phase so far

- Domain checks in the local CLI prevent mistakes; the hosted service (3d) is where they are enforced for every account.
- The HTTP twin is exercised by the Go end-to-end test, not yet by the Range gate in a cell.
