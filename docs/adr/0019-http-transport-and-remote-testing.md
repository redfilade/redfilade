# ADR-0019: Streamable HTTP transport and testing servers by URL

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Many MCP servers are reached over Streamable HTTP rather than stdio, and several L2 checks only exist there: token audience, rate limits and the 2026-07-28 routing headers (`Mcp-Method`, `Mcp-Name`). Testing a server by URL also means Redfilade sends attack traffic outside any cell, so it must never be pointed at a server the user does not control.

## Decision

- Add an HTTP transport **underneath** the existing client: each JSON-RPC line becomes one POST, and each message in a JSON or SSE response becomes one line. Limits, the refusal of server-initiated requests and frame recording stay shared with stdio.
- Send `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` for 2026-07-28; echo `Mcp-Session-Id` only for 2025-11-25. Never follow redirects. Record every exchange (status, outcome, `Retry-After`, `WWW-Authenticate`) for the oracle.
- New facts: `auth_bypassed`, `rate_limit_missing`, `header_mismatch_accepted`; L2 attacks `l2-token-audience` (family 01), `l2-rate-limit` (09), `l2-header-mismatch` (10).
- `redfilade test --url` runs only the attacks marked **remote-safe** (read-only payloads, no planted world, no sink). Until domain verification exists (Phase 3b), it accepts **loopback hosts only**. Tokens are read from environment variables named on the command line and redacted from all output.
- A bounded request budget is computed from the battery and shown on the consent screen.

## Consequences

- ✅ Builders can test HTTP servers, including authentication, before deploying them.
- ✅ The same oracle, evidence and SARIF work for stdio and HTTP targets.
- ⚠️ Remote runs have no cell: Redfilade sees only what the server returns. Reports say so.
- ⚠️ The rate-limit check is a coarse signal (40 requests, 8 at a time); a server limited by other means may still be reported.
- ⚠️ The audience check is only complete when the builder supplies a valid token for another audience (`--foreign-token-env`).

## Alternatives considered

| Option | Why not |
|---|---|
| A separate HTTP client | Would duplicate limits and recording, and drift from the stdio path |
| Allow any URL with a warning | Turns Redfilade into a general attack tool against other people's servers |
| Token on the command line | Leaks into shell history and process listings |

## Revisit when

Domain verification lands (Phase 3b), or the MCP HTTP transport changes again.
