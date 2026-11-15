# ADR-0021: L3 agent-in-the-loop scenarios

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

L3 tests what happens when a real AI agent uses an MCP server while an attack arrives through the data it reads (descriptions, outputs, other servers). A model's behaviour varies from run to run, so a single run proves little, and the attack's success depends on both the model and the server's own safeguards.

## Decision

- New scenario kind `agent` (level L3) with an `agent` block: the user's `task`, the number of `trials` (1–50) and `max_steps` (1–20). Agent scenarios have no exploit steps: the model acts.
- Each trial runs in a fresh cell with a fresh world and new canaries. The model gets a plain system prompt with no extra hardening, the task and the target's tools. Every tool call it makes goes through Redfilade's MCP client and is recorded.
- New fact `agent_leaked_canary`: the agent sent a canary in a tool call **and the server carried it out**. This measures the outcome a server can prevent, not only the model's intent.
- Verdict: exploited if any trial was. Reports also give the rate over completed trials and its 95% Wilson interval, and keep a redacted transcript per trial.
- Models: `scripted:naive` and `scripted:careful` are deterministic stand-ins that test the machinery and the twins in CI (the gate uses `scripted:naive`). `anthropic:<model-id>` calls the Messages API with `ANTHROPIC_API_KEY`, optionally through a model proxy (`REDFILADE_MODEL_BASE_URL`, ADR-0008).

## Consequences

- ✅ Builders can measure how often an agent using their server is hijacked, and whether server-side safeguards (here, a recipient allow-list) stop the damage.
- ✅ The gate stays deterministic and free: no API key or network in CI.
- ⚠️ Scripted models prove that the range works, not how real models behave. Real-model rates need `anthropic:` runs with enough trials, and cost API usage.
- ⚠️ With a real model, the task, tool list and tool outputs (synthetic data only) leave the machine for the model API; the consent screen says so.

## Alternatives considered

| Option | Why not |
|---|---|
| Judge the model's text ("did it agree to forward?") | Subjective and easy to game; the server-side effect is observable |
| One trial per run | A single sample of a random process says almost nothing |
| A real model in CI | Needs a secret in CI, costs money and makes the gate flaky |

## Revisit when

More model providers are needed, or scenarios need several servers at once (cross-server shadowing).
