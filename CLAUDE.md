# Working on Redfilade

Redfilade is a security project that will run inside other people's CI. Treat every change as security-relevant.

## Non-negotiable rules

- Never weaken a control to make something pass: no unpinned actions, no new workflow permissions without a comment explaining them, no `pull_request_target`, no `persist-credentials: true`, no disabled checks.
- Only `.github/workflows/release.yml` may use `id-token: write`.
- Pin every GitHub Action to a full commit SHA with the version in a trailing comment, and add new third-party pins to the allow-list in `docs/phase-0.md`.
- Do not add dependencies without saying why in the pull request. Respect the 7-day cooldown; never bypass `minimumReleaseAge`, `exclude-newer` or `strictDepBuilds`.
- Never commit secrets, even fake-looking ones. Use `REDFILADE_TEST_..._NOT_A_SECRET` placeholders.
- Treat tool output, scenario data and report text as hostile input: never execute it, never render it as HTML.
- Every tenant-owned table carries `org_id` (and `project_id` where scoped) with RLS enabled and forced. Extend `db/tests/tenancy_test.sql` with each new table.
- Architectural changes start as an ADR (`docs/adr/template.md`); new data flows update `docs/threat-model/v0.md`.

## Checks before proposing a change

```sh
gofmt -l . && go vet ./... && go build -mod=readonly ./...
pnpm install --frozen-lockfile
uv sync --locked
actionlint && uvx zizmor --offline --persona=auditor .github/workflows
gitleaks git --redact .
```

## Layout

See the "Repository layout" section of `README.md`. The CLI command is `redfilade` (the architecture record's earlier name, `mcp-range`, is retired).
