# Security policy

Redfilade is a security project, so a flaw in Redfilade itself is taken seriously, even at this early stage.

## Report a vulnerability privately

**Do not open a public issue, discussion or pull request for a security problem.**

Report it through GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/redfilade/redfilade/security/advisories/new)**

Please include what you found, the affected file or component, steps to reproduce, and the impact you believe it has. A minimal proof of concept helps; a working exploit against real third-party systems does not.

## What happens next

Redfilade is currently maintained by a small team, so these are honest targets rather than guarantees:

| Step | Target |
|---|---|
| We acknowledge your report | within 5 working days |
| We confirm or rule out the issue | within 14 days |
| A fix or mitigation is released | within 90 days of the report |
| Public advisory, with credit to you if you want it | when the fix ships, coordinated with you |

If an issue is being actively exploited, we will move faster and tell you what we're doing.

## In scope

Flaws in Redfilade's own code and infrastructure, for example:

- Escaping a run cell or sandbox, or reaching the host from inside one
- Reading or changing another tenant's projects, results or evidence
- Forging, altering or deleting signed evidence or reports
- Compromising our CI, release workflow, published packages or GitHub Action
- The CLI harming the machine it runs on: leaking files, keys or environment variables, or exposing its local control service
- Report output (SARIF, JUnit, HTML) that injects content into the tools that display it
- Secrets accidentally committed to this repository

## Out of scope

- **Weaknesses that a Range target is deliberately built to have.** Finding those is the point of the Range. They become in scope only if they let you escape the target's isolation.
- Vulnerabilities in third-party MCP servers or clients that you found *using* Redfilade. Report those to their own maintainers.
- Missing best practices with no demonstrated security impact
- Denial of service against hosted services through sheer traffic volume
- Social engineering of maintainers or contributors

## Supported versions

Redfilade has no released versions yet. Security fixes are made on `main`. Once releases begin, the latest minor version will receive fixes.

## Safe harbour

We will not pursue or support legal action against you for research that:

- stays within the scope above,
- uses only your own accounts, data and systems, or test targets provided by Redfilade,
- avoids privacy violations, data destruction and service disruption,
- stops and reports as soon as you have shown the issue, and
- gives us reasonable time to fix it before any public disclosure.

If you are unsure whether something is allowed, ask in your private report before you test it.

## Verifying what we publish

When releases begin, every artifact will be signed with [Sigstore cosign](https://docs.sigstore.dev/) and shipped with an SBOM and build provenance. Instructions for checking them will be in each release's notes. Do not run a Redfilade release you cannot verify.
