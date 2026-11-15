# Using the Range

The Range runs deliberately vulnerable MCP servers, attacks them, and decides what happened from facts it observes itself. Every scenario ships two builds of the same server, a **vulnerable twin** and a **secure twin**. The exploit must succeed on the first and fail on the second, or the scenario is broken.

## Requirements

- Docker (or a compatible CLI set in `REDFILADE_CONTAINER_CLI`). With gVisor's `runsc` runtime installed, Redfilade uses it automatically.
- Go 1.26 or newer to build the CLI and the targets.

Redfilade never runs a target directly on your machine. With no container runtime it refuses to run.

## Quick start

```sh
go build -o redfilade ./cmd/redfilade
scripts/build-targets.sh                 # builds redfilade-target/<name>:{vulnerable,secure}
./redfilade scenario list                # built-in scenarios
./redfilade scenario validate            # checks every built-in scenario
./redfilade range gate                   # runs every built-in scenario's twins and checks the outcomes
```

Run a single twin:

```sh
./redfilade range run l1-leaky-errors --build vulnerable
```

Test your own MCP server (packaged as an image) with the L1 or L2 battery (L2 includes L1):

```sh
./redfilade test --image ghcr.io/you/your-server:dev --level L2 --sarif results.sarif
```

Before anything runs, Redfilade shows what the cell can touch and waits for **y**. The default is No. In CI, pass `--yes`.

## What a cell gets

| | |
|---|---|
| Network | none (`--network none`), or for scenarios that need it a per-run internal network whose only other member is the egress sink |
| Filesystem | read-only root, a 16 MB no-exec `/tmp`, and the run's own `/world` |
| Privileges | non-root user 65532, all capabilities dropped, `no-new-privileges` |
| Limits | 256 MB memory, 1 CPU, 128 processes |
| Environment | empty, except variables the scenario declares |
| Never | your home folder, `~/.ssh`, cloud credentials, the Docker socket, the host network |

## Outputs

Each run writes to `--out` (default `redfilade-results/`):

- `evidence-*.json`: the full record, including every MCP frame with canaries redacted, world-file changes, the oracle's verdict and findings, what could **not** be observed, and the isolation tier.
- `--sarif FILE`: SARIF 2.1.0 for GitHub code scanning.
- `--junit FILE`: JUnit XML for CI dashboards.

Exit codes: `0` pass, `1` the attack succeeded (or the gate failed), `2` usage error, refusal or inconclusive run.

Local evidence is labelled **unsigned**. Only the release workflow signs evidence, with a keyless Sigstore signature tied to that workflow (ADR-0007).

## Verdicts

| Verdict | Meaning |
|---|---|
| `exploited` | The facts the scenario declares were observed |
| `not_exploited` | The run completed and none of them were observed |
| `inconclusive` | The run did not complete (crash, timeout), so the absence of findings proves nothing |

## Writing a scenario

A scenario is a directory under `scenarios/` with a `scenario.json` (ADR-0013). It is data only: no scripts or hooks run on the host.

```json
{
  "schema": "redfilade.scenario/v1",
  "id": "l1-leaky-errors",
  "title": "Error messages leak internals and secrets",
  "summary": "…",
  "family": "08", "level": "L1", "protocol": "2026-07-28", "risk": "low", "kind": "attack",
  "builds": {
    "vulnerable": { "image": "redfilade-target/leaky-errors:vulnerable" },
    "secure":     { "image": "redfilade-target/leaky-errors:secure" }
  },
  "needs": { "network": "none" },
  "world": [{ "path": "config/app.env", "content": "DB_PASSWORD={{canary.DB_PASSWORD}}\n" }],
  "exploit": [
    { "call": "lookup_customer", "arguments": { "id": "c-1001" } },
    { "battery": "l1-leaky-errors" }
  ],
  "oracle": { "match": "any", "checks": [
    { "fact": "canary_leaked", "canary": "DB_PASSWORD" },
    { "fact": "internals_leaked" }
  ]}
}
```

- **Canaries** (`{{canary.NAME}}`) get a fresh random value every run, so a leak cannot be faked by guessing.
- **Exploit steps** are MCP tool calls written as data, or a built-in battery attack.
- **Oracle facts** available today: `canary_leaked` (a canary crossed from the target to the client), `internals_leaked` (stack traces, source paths, connection strings), `world_file_changed`, `secret_pattern_leaked` (well-known credential formats), `sensitive_file_read` (system file contents in replies), `egress_reached_sink` and `canary_egressed` (with `"needs": {"network": "sink"}`).

Targets live in `targets/<name>/` as a Go program built twice with `-X main.mode=vulnerable|secure`, into `FROM scratch` images by `scripts/build-targets.sh`.

## Scenario packs

A directory with a `scenario.json` that is not built into your binary is an **external pack** (ADR-0016). Its identity is the sha256 of the exact file:

```sh
./redfilade pack digest ./my-pack        # sha256:…
./redfilade pack verify ./my-pack        # verified, unsigned, unverifiable or invalid
```

| Signature | What happens |
|---|---|
| verified (signed by our release workflow, checked with `cosign`) | Runs after consent; both images must be pinned by digest |
| invalid | Always refused |
| unsigned or unverifiable | Refused unless you pass `--allow-unsigned` and confirm the pack id (typed at the prompt, or `--confirm ID`). Without a terminal you must also allow the exact digest with `--allow-digest sha256:…` or `--allowlist FILE` |

```sh
./redfilade range run ./my-pack --build vulnerable --allow-unsigned
./redfilade range gate ./my-pack --yes --allow-unsigned --confirm my-pack --allow-digest sha256:…
```

## Contributing a scenario

Open a pull request that adds `scenarios/<id>/scenario.json` (the directory name must equal the id). A maintainer reviews it and applies the `triage` label; `triage.yml` then runs it against the twins built from the base branch, with no secrets, and writes a summary to the job page. New twins are reviewed and merged before scenarios that use them can be triaged.
