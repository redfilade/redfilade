# ADR-0013: Scenarios are data, judged by facts

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Every scenario must ship a vulnerable and a secure build, and CI must prove the exploit succeeds on the first and fails on the second (design doc, "Proposed architecture"). Existing labs score attacks by captured flags, which can be guessed or read from the repo. Contributed scenarios are hostile by design (architecture record 10.3), so anything that *runs* on a reviewer's or user's machine is attack surface.

## Decision

A scenario is a directory with a strict JSON manifest, `scenario.json`, validated with unknown fields rejected:

- identity: `id`, `title`, register `family` (01–26), test `level` (L1–L5), `protocol`, `risk` (`low` | `escape`)
- `builds.vulnerable` and `builds.secure`: the target image for each twin
- `needs`: what the cell may use (`network`: `none` | `sink`; `world` files). Anything not declared is denied.
- `world`: files to seed into the synthetic organisation, with `{{canary.NAME}}` placeholders
- `exploit`: an ordered list of **MCP calls as data** (tool name and arguments, which may reference canaries). No scripts, no hooks, nothing executed on the host.
- `oracle`: the facts that prove the exploit worked, for example "canary X crossed from server to client" or "world file Y changed". The verdict is computed from observations, never from the target's own claims.

Manifests are JSON, not YAML. That removes a parser with a history of resource-exhaustion bugs (YAML bombs) and keeps the Go core dependency-free.

## Consequences

- ✅ Exploits are reviewable data, and a pack cannot run code on the host.
- ✅ Every result is reproducible from the manifest plus the image digests.
- ⚠️ Attacks that need a programmable client (timing, multi-step adaptive logic) need a richer, still declarative step language later.

## Alternatives considered

| Option | Why not |
|---|---|
| YAML manifests | Parser complexity and YAML-bomb risk for no real benefit |
| Exploits as scripts | Code from contributors would run on reviewers' machines |
| Flags (`FLAG{...}`) | Guessable and readable from the public repo |

## Revisit when

An attack class cannot be expressed as declarative MCP calls.
