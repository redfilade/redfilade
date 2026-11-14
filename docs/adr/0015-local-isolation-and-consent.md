# ADR-0015: Local isolation tiers and a consent gate

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

ADR-0001 isolates hosted and CI runs in microVMs and uses gVisor on laptops. Until the microVM runner exists, the CLI must still never expose the user's machine, and it must be honest about how strong the isolation really is (architecture record 10.4 and 10.5).

## Decision

The CLI runs each target in a container and detects the isolation tier: `gvisor` (Docker with the `runsc` runtime) or `docker` (plain runc). Every cell runs with:

- no network (`--network none`) unless the scenario declares the egress sink
- read-only root filesystem, all capabilities dropped, `no-new-privileges`, a non-root user, process, memory and CPU limits, and a small no-exec `/tmp`
- no host mounts except the run's own world directory; never the home folder, `~/.ssh`, cloud credentials or the Docker socket
- an empty environment except variables the scenario explicitly declares

Scenarios marked `risk: escape` refuse to run on the `docker` tier.

Before a run, the CLI shows a consent screen built **only** from the validated manifest (target images, network, world files, isolation tier, risk). The default answer is No. Non-interactive runs (CI) must pass `--yes`.

Reports always state the isolation tier and that they come from an unsigned local run, unless signed by the release workflow.

## Consequences

- ✅ A target cannot read the user's files, keys or network by default.
- ✅ The user sees, before running, exactly what a scenario can touch, in text the scenario author did not write.
- ⚠️ Plain Docker shares the host kernel. That is acceptable only for low-risk scenarios and is shown in every report.

## Alternatives considered

| Option | Why not |
|---|---|
| Run targets directly on the host | The mistake the Appsecco lab makes |
| Require gVisor everywhere | Blocks Windows and macOS users today |

## Revisit when

The microVM runner (ADR-0001) ships for local use.
