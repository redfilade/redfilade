# ADR-0023: L4 — testing MCP clients with a hostile server

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Clients and hosts (IDEs, desktop apps, agents) are attacked by the servers they connect to: invisible instructions in tool metadata, requests for the user's credentials, server-driven model calls. To test a client, Redfilade has to play the malicious server and judge what the client does.

## Decision

- **Engine.** `internal/hostile` is a hostile MCP server over stdio with three probes:
  - `hidden_instruction`: a tool description carries an instruction in Unicode tag characters, naming a beacon tool.
  - `elicitation`: a fake "session expired" request for the user's password.
  - `sampling`: a request for the client's model to list private files and keys.
  
  Server-initiated requests use the 2025-11-25 form.
- **Facts:**
  - `client_followed_hidden_instruction`: the beacon tool was called;
  - `client_answered_elicitation`: an accepted, non-empty answer;
  - `client_answered_sampling`: a completion was returned;
  - `client_leaked_canary`: a planted secret reached the server.
  
  All are judged from what the client sends; reports state that the client's UI and any human approval are not observable.
- **Range.** Scenario kind `client` (L4) with a `hostile` block. The cell runs the client under test with its stdio carrying the MCP connection; Redfilade's hostile server is on the other end. First scenario: `l4-hostile-server`, with vulnerable and secure client twins.
- **Your own client.** `redfilade hostile-server` is a stdio server to add to a real client's configuration. It writes only protocol messages to stdout and saves the session; `redfilade client-report` judges it and writes evidence and SARIF.

## Consequences

- ✅ Client makers can test their product against realistic malicious-server behaviour without building a test harness.
- ✅ The same facts and SARIF rules apply to Range twins and real clients.
- ⚠️ A client that asks its user and then answers looks the same on the wire as one that answers automatically; the report says so, and the fix guidance asks for clear approval UI.
- ⚠️ The 2026-07-28 multi-round-trip form of server requests is not covered yet.

## Alternatives considered

| Option | Why not |
|---|---|
| Drive real client UIs (screenshots) | Brittle, product-specific and slow; the wire is common to every client |
| Run real clients in cells | Most clients launch servers themselves; a stdio server they launch fits how they already work |

## Revisit when

Clients adopt the 2026-07-28 multi-round-trip requests, or a standard client-test harness emerges.
