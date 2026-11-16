# Contributing to Redfilade

Thank you for helping make MCP safer. This guide covers how to contribute without weakening the project you're improving.

> **Security issues in Redfilade itself go to [SECURITY.md](SECURITY.md), not to issues or pull requests.**

## Before you start

- Read the [Code of Conduct](CODE_OF_CONDUCT.md), including its ethical rules.
- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Architectural changes start as an Architecture Decision Record. Copy [`docs/adr/template.md`](docs/adr/template.md).

## Set up your machine

You need Git, [pre-commit](https://pre-commit.com), Go, Node.js with [pnpm](https://pnpm.io) (exact version in `package.json`), and Python with [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/redfilade/redfilade
cd redfilade
pre-commit install          # gitleaks blocks secrets before they are committed
pnpm install --frozen-lockfile
uv sync --locked
go build ./...
```

`pnpm install` will not run dependency install scripts; that is intentional (see below).

## Commit rules

- **Sign your commits** with an SSH or GPG key. `main` only accepts verified commits. GitHub's guide: [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).
- **Sign off your commits** (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change or have the right to submit it under the terms below.
- Keep commits focused and messages descriptive.

## Licensing of your contribution

Redfilade is source-available under your choice of the PolyForm Noncommercial or PolyForm Internal Use license ([`LICENSE`](LICENSE)), and its use is governed by [`DISCLAIMER.md`](DISCLAIMER.md). By submitting a contribution you agree that:

- everyone may use your contribution under the project's licenses; and
- you also license your contribution to the licensor, Sanket Toraskar, under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), so the project can keep maintaining, relicensing and operating Redfilade without asking every contributor again.

You keep the copyright in your contribution. Only contribute attacks for learning and defence, and never include real credentials, personal data or working attacks against systems you do not own.

## Pull requests

- Every change to `main` goes through a pull request with signed commits, and all status checks must pass. A code-owner review becomes required once the project has a second maintainer.
- Pull requests from forks run in the **untrusted lane**: no secrets, no publishing rights, read-only token. A maintainer approves the first workflow run for new contributors.
- Changes to `.github/`, lockfiles, dependency policy, the harness, the oracle or signing code need a review from a code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).

## Dependency policy

A poisoned dependency is the easiest way into a project like this, so:

- **New dependencies are a reviewed decision.** In your pull request, say why it's needed and include its age, maintainers, download count, size and whether it has install scripts. Prefer the standard library.
- **7-day cooldown.** pnpm and uv refuse package versions published in the last 7 days; Renovate waits the same 7 days before proposing updates.
- **No install scripts.** pnpm blocks dependency build scripts. Any exception is listed explicitly in `pnpm-workspace.yaml` and owned by CODEOWNERS.
- **Lockfiles are law.** CI installs with `--frozen-lockfile`, `uv sync --locked` and `-mod=readonly`. Commit lockfile changes together with the change that caused them.

## Rules for every change

Redfilade runs inside other people's CI, so every change is security-relevant:

- Never weaken a control to make something pass: no unpinned actions, no `pull_request_target`, no `persist-credentials: true`, no disabled checks. A new workflow permission needs a comment explaining it.
- Only `.github/workflows/release.yml` may use `id-token: write`.
- Pin every GitHub Action to a full commit SHA with the version in a trailing comment, and add new third-party pins to the allow-list in [`docs/phase-0.md`](docs/phase-0.md).
- Treat tool output, scenario data and report text as hostile input: never execute it, never render it as HTML.
- Every tenant-owned table carries `org_id` (and `project_id` where scoped) with row-level security enabled and forced; extend `db/tests/tenancy_test.sql` with each new table.
- New data flows update [`docs/threat-model/v0.md`](docs/threat-model/v0.md).

## Never commit secrets

Not even test or "dummy" keys that look real. Use obviously fake values like `REDFILADE_TEST_TOKEN_NOT_A_SECRET`. Secret scanning with push protection, plus the gitleaks hook, will block most mistakes, but don't rely on them.

## Contributing attacks

New scenarios are data-only manifests that go through the triage lane before review; see [Contributing a scenario](docs/range.md#contributing-a-scenario). For an idea without a scenario, open an issue with the *Attack idea* template, without working exploit code for unpatched third-party software.
