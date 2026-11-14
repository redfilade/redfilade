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
- **Sign off your commits** (`git commit -s`) to certify the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change or have the right to submit it under the Apache-2.0 licence.
- Keep commits focused and messages descriptive.

## Pull requests

- Every change to `main` goes through a pull request with at least one approving review, and all status checks must pass.
- Pull requests from forks run in the **untrusted lane**: no secrets, no publishing rights, read-only token. A maintainer approves the first workflow run for new contributors.
- Changes to `.github/`, lockfiles, dependency policy, the harness, the oracle or signing code need a review from a code owner (see [`.github/CODEOWNERS`](.github/CODEOWNERS)).

## Dependency policy

A poisoned dependency is the easiest way into a project like this, so:

- **New dependencies are a reviewed decision.** In your pull request, say why it's needed and include its age, maintainers, download count, size and whether it has install scripts. Prefer the standard library.
- **7-day cooldown.** pnpm and uv refuse package versions published in the last 7 days; Renovate waits the same 7 days before proposing updates.
- **No install scripts.** pnpm blocks dependency build scripts. Any exception is listed explicitly in `pnpm-workspace.yaml` and owned by CODEOWNERS.
- **Lockfiles are law.** CI installs with `--frozen-lockfile`, `uv sync --locked` and `-mod=readonly`. Commit lockfile changes together with the change that caused them.

## Never commit secrets

Not even test or "dummy" keys that look real. Use obviously fake values like `REDFILADE_TEST_TOKEN_NOT_A_SECRET`. Secret scanning with push protection, plus the gitleaks hook, will block most mistakes, but don't rely on them.

## Contributing attacks

Scenario packs and new targets will open in **Phase 2**, together with the signing and triage process that keeps reviewers safe. Until then, please describe new attack ideas in an issue using the *Attack idea* template, without working exploit code for unpatched third-party software.
