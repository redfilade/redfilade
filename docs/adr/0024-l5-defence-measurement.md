# ADR-0024: L5 — measuring defences

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

MCP gateways and guardrails claim to stop attacks. A useful measurement needs two numbers, not one: how many real attacks the defence stops, and how much normal work it breaks. A defence that blocks everything scores perfectly on the first and is useless.

## Decision

- **Protocol `redfilade.defence/v1`.** The defence is a container image that reads one JSON line per MCP message on stdin, `{"direction":"client_to_server"|"server_to_client","message":…}`, and answers one line, `{"action":"allow"|"block","reason":…}`. It is product-neutral: a real gateway is wrapped by a small adapter.
- **Fail closed.** A malformed answer, a crash or a decision slower than 5 s counts as a block. A blocked request gets a JSON-RPC error back; a blocked response is replaced by one.
- **Isolation.** The defence runs in its own cell: no network, read-only, all privileges dropped, an empty world. It sees messages only through Redfilade.
- **Attacks.** Every built-in `attack` and `agent` scenario runs against its **vulnerable** twin with the defence in the path. `not_exploited` means stopped. An `inconclusive` run in which the defence blocked messages also counts as stopped (the attack never got to run); an inconclusive run with nothing blocked is left out of the rate.
- **Benign set.** `internal/defence/benign.json` holds ordinary tasks (look up a customer, read a document, query a name with an apostrophe) run against the **secure** twins. Every blocked benign call is a false positive.
- **Output.** Block rate and false-positive rate, each with a Wilson 95% interval, printed and written to `defence-report.json` (`redfilade.defence-report/v1`). `--min-block-rate` and `--max-false-positive-rate` turn it into a CI gate.
- **Range twin.** `targets/defence-rules`: the vulnerable build allows everything, the secure build applies strict rules. The e2e test requires the strict build to stop path traversal, SQL injection, command injection and SSRF with zero false positives, and the permissive build to stop nothing.

## Consequences

- ✅ Defence vendors and buyers get a repeatable, two-sided score from the same scenarios builders use.
- ✅ The protocol is small enough to wrap any gateway in a few dozen lines.
- ⚠️ The benign set is small, so the false-positive interval is wide; it grows with every scenario.
- ⚠️ The defence image is the user's own and may be pulled when missing, unlike Range twins (`--pull never`); the consent screen says so.
- ⚠️ L4 client scenarios are not run through defences yet.

## Alternatives considered

| Option | Why not |
|---|---|
| Put the defence on the network as an HTTP proxy | Needs networking between cells and a different adapter per product; stdio keeps the defence offline |
| Score block rate alone | Rewards blocking everything |
| Fail open on errors | A crashing defence would look like a working one |

## Revisit when

A common gateway interface appears, or the benign set is large enough to report per-family false-positive rates.
