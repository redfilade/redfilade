# ADR-0018: Reuse Cisco MCP Scanner's detection rules with our own engine

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Tool poisoning and prompt injection reach a model through the text an MCP server sends: tool descriptions, parameter descriptions and tool output. Redfilade's oracle had no way to judge that text. Cisco's MCP Scanner (Apache-2.0) maintains 10 YARA rules for exactly these threats, with tests and an evaluation set of malicious example servers.

## Decision

- Copy the 10 rule files **unmodified** into `internal/rules/cisco/`, with Cisco's license, a source note pinning the upstream commit and SHA-256 checksums. They stay under Apache-2.0.
- Evaluate them with **our own Go engine** (`internal/rules`) built on RE2, not with YARA or Cisco's Python code. It supports only the YARA features the rules use (regex and text strings, boolean conditions, `any/all of them`, match counts, offsets, lengths and `for any|all` loops) and refuses everything else.
- Prove equivalence with a **golden corpus**: `scripts/cisco-rules-golden.py` reads Cisco's test fixtures with `ast` (never executing them), records what the reference engine (yara-python) matches, and the Go tests require identical results. Fixture values shaped like credentials are replaced with placeholders first.
- Add two oracle facts: `tool_metadata_flagged` (tool descriptions and parameters, all rules) and `output_injection_flagged` (tool output; prompt-injection, coercive-injection and script-injection rules only).
- Add the `l1-tool-poisoning` battery check and Range scenario with a vulnerable and a secure twin.

## Consequences

- ✅ Builders get a tool-poisoning check at L1, with rules maintained by a large security team.
- ✅ No new runtime dependency, no cgo, no Python; hostile text cannot cause catastrophic backtracking.
- ✅ Equivalence is measured: all 237 fixtures from Cisco's tests, and 2,464 samples from Cisco's evaluation set checked locally, match the reference engine exactly.
- ⚠️ Rule updates need a manual review, a new golden corpus and possibly engine support for new syntax; unsupported syntax fails loudly at load time and in CI.
- ⚠️ These rules are text heuristics: a match is a strong signal, not proof of intent. Reports name the rule and show the matched text.
- ⚠️ Text over 64 KiB per field, or over 1 MiB per run, is not scanned; reports say so.

## Alternatives considered

| Option | Why not |
|---|---|
| Run Cisco's scanner as a subprocess | Adds Python, its dependency tree and optional cloud APIs to every run |
| Link libyara through cgo | cgo breaks static `FROM scratch` builds and adds a C parser of untrusted input |
| Write our own rules from scratch | Slower and weaker than reusing a maintained, tested rule set |

## Revisit when

Cisco changes the rule format substantially, or Redfilade needs rules from more sources.
