# Phase 0: foundation

Phase 0 is done when every item below is ticked. No feature code lands before that.

## Checklist

| # | Item | Where | Status |
|---|---|---|---|
| 1 | GitHub organisation with secure two-factor authentication required | Org settings | ✅ Org created and locked down · ⬜ confirm 2FA requirement saved |
| 2 | Rulesets on `main`: pull request, signed commits, status checks, no force push; CODEOWNERS on sensitive paths | [`.github/rulesets/`](../.github/rulesets/), [`.github/CODEOWNERS`](../.github/CODEOWNERS) | ✅ Committed · ⬜ import (step A) |
| 3 | Actions hardened: SHA pins, read-only token, untrusted and trusted lanes, Renovate with a 7-day cooldown | [`.github/workflows/`](../.github/workflows/), [`renovate.json`](../renovate.json) | ✅ Committed · ⬜ allow-list actions (step C), install Renovate (step D) |
| 4 | Secret scanning with push protection, plus a gitleaks pre-commit hook | Org security configuration, [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) | ✅ Done |
| 5 | Dependency policy committed: pnpm settings, uv lock, `go.sum` | [`pnpm-workspace.yaml`](../pnpm-workspace.yaml), [`.npmrc`](../.npmrc), [`pyproject.toml`](../pyproject.toml), [`uv.lock`](../uv.lock), [`go.mod`](../go.mod) | ✅ Committed. `go.sum` appears with the first Go dependency; CI already builds with `-mod=readonly` |
| 6 | `SECURITY.md`, threat model v0 (STRIDE on the four planes), ADR-001 to ADR-012 | [`SECURITY.md`](../SECURITY.md), [`threat-model/v0.md`](threat-model/v0.md), [`adr/`](adr/) | ✅ Committed |
| 7 | Multi-tenant schema skeleton: `org_id`, `project_id`, RLS migration, UUIDv7 | [`db/migrations/0001_tenancy.sql`](../db/migrations/0001_tenancy.sql), [`db/tests/tenancy_test.sql`](../db/tests/tenancy_test.sql) | ✅ Committed; isolation test passes on Postgres 18 |
| 8 | Release workflow proven with a dry-run `0.0.1`: cosign signature, SBOM, provenance | [`.github/workflows/release.yml`](../.github/workflows/release.yml) | ✅ Committed · ⬜ run the dry run (step E). Trusted publishing to npm and PyPI is added with the first published package |

## One-time steps for an org owner

Do these in order, after the first commit is on `main`.

### A. Import the rulesets

Wait until the `ci` workflow has run once on `main`, so the status checks exist. Then, for each file in `.github/rulesets/`:

1. Repository **Settings → Rules → Rulesets → New ruleset → Import a ruleset**.
2. Choose the JSON file, review, and **Create**.

| File | What it enforces |
|---|---|
| `main-integrity.json` | No deletion or force push, linear history, signed commits, pull requests only, all four CI checks green. **Nobody can bypass it.** |
| `main-review.json` | One approving review from a code owner, re-approval after new pushes. Org owners may merge their *own* pull requests without a second reviewer, but still only through a pull request that passes every check above. Remove the bypass when a second maintainer joins. |
| `release-tags.json` | Only org owners can create `v*` tags; tags can never be moved or deleted. |

### B. Create the protected release environment

Repository **Settings → Environments → New environment** named `release`:

- **Required reviewers:** yourself (later, the maintainers team).
- **Deployment branches and tags:** *Selected branches and tags* → add branch `main` and tag pattern `v*.*.*`.
- Add **no secrets**. Releases sign with short-lived OIDC identity, not stored keys.

### C. Allow-list the third-party actions

Org **Settings → Actions → General → Allow specified actions and reusable workflows**. Paste these exact pins, one per line (GitHub's own `actions/*` and `github/*` are already allowed):

```text
step-security/harden-runner@1d88384fd173af6ecb012dfd0264a306b711241a
pnpm/action-setup@73e46992e05b19abd31f2f3c20e0e7370d762115
astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2
ossf/scorecard-action@fa7117db83c52d787ae5a89f350999701505d78e
sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532
anchore/sbom-action@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c
google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@32d3cd482bdadfb38b186c0ad1b031902d55d932
google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@32d3cd482bdadfb38b186c0ad1b031902d55d932
```

When Renovate bumps a pin, update this list in the same review.

### D. Install Renovate

Install the **Mend Renovate** GitHub App on the org with **Only select repositories → redfilade/redfilade**. It reads `renovate.json`: 7-day cooldown, SHA-pinned actions, no automerge.

### E. Prove the release pipeline (dry run 0.0.1)

1. **Actions → release → Run workflow** on `main`, version `0.0.1`.
2. Approve the `release` environment when asked.
3. Check the run: binaries, source archive, SPDX SBOM, `checksums.txt` with a verified cosign bundle, and a build-provenance attestation. Nothing is published.

### F. Repository presentation

- **Settings → General → Social preview:** upload `assets/brand/redfilade-social-1280x640.png`.
- Org **Settings → General → Profile picture:** upload `assets/brand/redfilade-avatar-1024.png`.
- **Settings → General → Features:** turn on **Discussions**.

## After Phase 0

- Switch `step-security/harden-runner` from `audit` to `block` with the endpoint allowlist from baseline runs.
- Add a CI job that runs `db/tests/tenancy_test.sql` against a digest-pinned Postgres image.
- Replace `@sankettheinventor` in CODEOWNERS with a `@redfilade/maintainers` team.
