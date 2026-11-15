# ADR-0014: A fresh synthetic organisation with random canaries for every run

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

The oracle needs something that unambiguously proves a boundary was crossed. Fixed secrets in the repo can be read instead of stolen. Real data must never be used.

## Decision

Every run creates a new synthetic organisation in a temporary world directory:

- Canaries are generated per run with a cryptographic random source, in the form `CANARY_<NAME>_<26 base32 chars>`. They are never written to the repository or to logs before the run ends.
- World files are rendered from the scenario's templates and mounted into the cell. Their hashes are recorded before and after the run.
- Canary values are kept outside the cell, in the run record that only the oracle reads.

## Consequences

- ✅ A canary seen outside its file is proof of a leak, and it cannot be guessed in advance.
- ✅ Nothing real can leak, because nothing real is present.
- ⚠️ Evidence bundles contain the run's canaries. They are worthless outside that run, but reports still redact them by default.

## Alternatives considered

| Option | Why not |
|---|---|
| Fixed flags | Guessable, readable from the repo |
| Real-looking sample data | Risk of resembling real people or credentials |

## Revisit when

Scenarios need long-lived synthetic state across runs (a shared Range backend).
