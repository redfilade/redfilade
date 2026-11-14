# ADR-0009: Sign-in through GitHub OAuth and enterprise SSO

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

Storing passwords is a liability with no benefit. Enterprises require single sign-on and automatic offboarding.

## Decision

**GitHub OAuth** for the community; **OIDC/SAML SSO with SCIM** for enterprise. No passwords are stored (`users.idp` in the schema).

## Consequences

- ✅ No password database to breach.
- ✅ Offboarding happens in the customer's identity provider.
- ⚠️ Community users need a GitHub account.

## Alternatives considered

| Option | Why not |
|---|---|
| Our own passwords | A liability with no benefit. |

## Revisit when

Demand from communities outside GitHub.
