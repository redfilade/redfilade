# ADR-0017: Source-available license: noncommercial or internal use

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Redfilade publishes vulnerable targets and attack code for learning and research. The maintainer wants:

- anyone, including commercial companies, to be able to test **their own** MCP servers and clients with it;
- nobody to copy the code to sell it, host it for others, or build their own product on it;
- it to be clear that people who misuse it are responsible for what they do.

The project was first published under the Apache License 2.0, which allows all of the above, including resale.

## Decision

- Offer the code under a **choice of two standard licenses**: PolyForm Noncommercial 1.0.0 (learning, research, sharing noncommercially) **or** PolyForm Internal Use 1.0.0 (any organisation, including companies, using and changing it internally, with no distribution). SPDX: `PolyForm-Noncommercial-1.0.0 OR LicenseRef-PolyForm-Internal-Use-1.0.0`. The licensor is named in the Required Notice. No other license is offered.
- Describe the project as **source-available**, not "open source".
- Put use conditions in **`DISCLAIMER.md`**: authorised targets only, sole responsibility of the user, no warranty, verify before running. Keep the name and logo out of the licenses (**`TRADEMARKS.md`**).
- Contributors license their work to everyone under the project licenses and to the licensor under Apache-2.0, so the project can still be maintained and relicensed (`CONTRIBUTING.md`).

## Consequences

- ✅ Students, researchers and teachers can use, change and share it.
- ✅ Companies can run it on their own systems and in their own CI to test their own MCP servers, free.
- ✅ Neither license allows selling it, hosting it for others, or distributing it in a product.
- ✅ Both licenses carry the same "No Liability" clause, and the disclaimer states that users are responsible for their use.
- ⚠️ Companies cannot share their changes publicly (Internal Use forbids distribution); they can contribute them upstream instead.
- ⚠️ Edge cases, such as a consultant running it for a client, are not spelled out by either license; the maintainer answers them case by case.
- ⚠️ Some communities and registries accept only OSI-approved licenses.
- ⚠️ Copies published before this change stay available under Apache-2.0; that cannot be revoked.
- ⚠️ No license removes liability the law itself imposes. These terms should be reviewed by a lawyer before a public launch.

## Alternatives considered

| Option | Who uses it | Why not |
|---|---|---|
| Apache-2.0 plus a disclaimer | Cisco's MCP Scanner | Allows anyone to copy, sell and build products on the code |
| PolyForm Noncommercial only | Many research projects | Blocks companies from testing their own servers, which is the builder use case |
| PolyForm Shield | WebPageTest | Only bans products that compete with us; non-competing products could still be built on our code |
| Elastic License 2.0 | Elasticsearch, Airbyte | Allows building and redistributing products; only bans managed services |
| Functional Source License | Sentry | Bans competing use, but turns into Apache or MIT after two years |
| Internal business use only, single license | Semgrep's rules | Closest in spirit, but alone it would stop learners sharing their changes; pairing it with Noncommercial covers both |

## Revisit when

A paid offering, a demand for redistribution by companies, or an external contributor community makes these limits a blocker.
