# ADR-0020: Domain proofs, live re-checks and address pinning for remote tests

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

ADR-0010 allows remote tests only against verified domains. The CLI needs a concrete proof format, a rule for subdomains, and protection against a verified name being pointed at someone else's machine.

## Decision

- **Proofs.** `redfilade domain challenge` issues a random token (`redfilade-verify=` + 160 random bits). It is published as a DNS TXT record at `_redfilade-challenge.<domain>` or as the body of `https://<domain>/.well-known/redfilade-challenge`. Redirects never count.
- **Scope.** A DNS proof covers the domain and its subdomains (it shows control of the zone). A file proof covers only its exact host.
- **Live re-check.** The proof is checked again before every remote run; removing it revokes testing immediately. The local store (`domains.json`, mode 0600) only remembers tokens and history.
- **Addresses.** The host is resolved once. If any answer is loopback, private, link-local (including cloud metadata), CGNAT, multicast or reserved, the run is refused. Every connection is pinned to the first answer, so DNS cannot move the run elsewhere.
- **Transport.** Remote hosts are tested over HTTPS only; IP literals cannot be verified and are refused (loopback excepted).

## Consequences

- ✅ Redfilade cannot be pointed at a server the user has not proven control of, or at an internal network through a verified name.
- ✅ The same verifier is reused by the hosted Test Bench (Phase 3d), which adds the per-account audit trail of ADR-0010.
- ⚠️ In the local CLI these checks guard against mistakes, not a determined user, who could modify the source. The hosted service is where they are enforced against everyone.
- ⚠️ Servers behind CDNs that answer from several addresses are pinned to one of them for the run.

## Alternatives considered

| Option | Why not |
|---|---|
| Trust a locally cached verification | Ownership changes; a lapsed domain could still be attacked |
| Allow file proofs to cover subdomains | Control of one web host does not prove control of the zone |
| Resolve on every connection | Opens DNS rebinding to internal addresses mid-run |

## Revisit when

A standard ownership proof for MCP servers emerges, or the hosted service needs organisation-wide verification.
