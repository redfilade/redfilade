# ADR-0016: Signed scenario packs and an isolated triage lane

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Phase 2 opens the Range to scenarios we did not write: packs downloaded by users and scenarios contributed through pull requests. A scenario is data (ADR-0013), but it still decides which twin image runs, what the cell's world holds, which network it gets and what the attacker sends. A user must be able to tell a reviewed pack from an arbitrary one, and the project must be able to run contributions without trusting them.

## Decision

1. **Built-ins are embedded.** Scenarios under `scenarios/` are compiled into the binary and run by id (`redfilade range run l2-ssrf`). `range gate` with no arguments runs all of them.
2. **A pack's identity is its digest.** An external pack is a directory with a `scenario.json`; its identity is `sha256` over the exact file bytes (`redfilade pack digest`). Any edit is a different pack.
3. **Signatures are keyless and bound to our release workflow.** `release.yml` signs each scenario with cosign and writes `scenario.json.sigstore.json`. A pack counts as verified only if `cosign verify-blob` accepts it for the identity `.github/workflows/release.yml` on `main` or a version tag, issued by GitHub Actions.
4. **Policy before consent.** The CLI decides before the consent screen is shown:
   - an invalid signature is always refused;
   - a verified pack must pin both images by digest;
   - an unsigned pack needs `--allow-unsigned` and its id, typed at the prompt or given with `--confirm`;
   - a non-interactive unsigned run also needs the exact digest (`--allow-digest` or `--allowlist`).
   The consent screen then shows the source and signature state.
5. **Triage lane.** Contributed scenarios run in `triage.yml`, started only when a maintainer applies the `triage` label. The CLI and twins are built from the base commit; the pull request is checked out as data, and only regular `scenarios/<id>/scenario.json` files are copied out. Each runs under the pack policy with its id confirmed and its digest allowed for that run. No secrets, no OIDC, read-only token. The job summary is produced by the trusted CLI (`redfilade triage summarize`) from allow-listed fields only.

## Consequences

- ✅ Users see exactly where a scenario came from and whether we signed it, before anything runs.
- ✅ A pack cannot be swapped after approval: the digest pins the exact bytes.
- ✅ Contributions get real Range runs without any contributor code being built or executed on the runner.
- ⚠️ Verifying signatures needs `cosign` on the user's PATH; without it a signed pack is treated as unverifiable and must be allowed like an unsigned one.
- ⚠️ A contributed scenario that needs a new twin cannot be triaged until a maintainer merges the twin, because range runs never pull images.
- ⚠️ Results are not commented on the pull request. Posting would need a write token in a `workflow_run` job that reads untrusted artifacts; maintainers read the job summary instead.

## Alternatives considered

| Option | Why not |
|---|---|
| Long-lived signing key in the repository or a secret | A leaked key signs anything forever; keyless signing ties each signature to one workflow run (ADR-0007) |
| Trust packs by name or URL | Names and URLs can be reused; a digest cannot |
| Build contributed twins in triage | Building runs contributor-controlled code paths on the runner; twins are reviewed and merged first |
| `pull_request_target` with a comment bot | Forbidden in this repository: it runs with a write token next to untrusted input |
| Comment through a `workflow_run` job | Adds a write-capable job that consumes untrusted artifacts; not worth it for a summary maintainers can already read |

## Revisit when

- Community packs are distributed outside this repository (then a pack index with its own signer may be needed), or
- maintainers ask for in-PR comments often enough to justify a hardened comment job.
