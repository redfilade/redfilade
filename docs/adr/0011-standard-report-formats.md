# ADR-0011: Standard report formats

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Builders should see findings where they already work.

## Decision

Reports ship as **SARIF** (code scanning), **JUnit** (CI), **signed JSON evidence** and **HTML**. All report text is escaped; raw tool output never appears in titles or messages.

## Consequences

- ✅ Integrates with GitHub, GitLab and CI dashboards without plugins.
- ⚠️ Report text becomes an injection surface in other tools, so escaping is mandatory and tested.

## Alternatives considered

| Option | Why not |
|---|---|
| Custom format only | Nobody integrates it. |

## Revisit when

A new standard for AI-security findings gains adoption.
