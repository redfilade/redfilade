# ADR-0007: Keyless signing of results and releases

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Builders must be able to trust a result they did not watch, and users must be able to trust our releases.

## Decision

**Sigstore keyless** signing for public results and releases, issued to the release workflow's OIDC identity. **cosign with a cloud KMS key** for self-hosted and air-gapped installs. Only `.github/workflows/release.yml` may hold `id-token: write`.

## Consequences

- ✅ No long-lived signing key exists to steal.
- ✅ Anyone can verify against the public transparency log.
- ⚠️ Air-gapped verification needs a separate trust root.

## Alternatives considered

| Option | Why not |
|---|---|
| GPG keys | Long-lived secrets. |
| Our own PKI | A large system to run and audit. |

## Revisit when

Sigstore's public infrastructure becomes unavailable or unsuitable for enterprise customers.
