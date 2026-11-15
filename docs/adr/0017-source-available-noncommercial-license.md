# ADR-0017: Source-available, noncommercial license

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

Redfilade publishes vulnerable targets and attack code for learning and research. The maintainer wants it free for anyone to learn from, but not sold or used commercially, and wants it clear that people who misuse it are responsible for what they do. The project was first published under the Apache License 2.0.

## Decision

- License the code under the **PolyForm Noncommercial License 1.0.0**, with the licensor named in the Required Notice. No commercial license is offered.
- Describe the project as **source-available**, not "open source", because the Open Source Definition forbids restrictions on commercial use.
- Put use conditions in **`DISCLAIMER.md`**: authorised targets only, sole responsibility of the user, no warranty, verify before running. Keep the name and logo out of the license (**`TRADEMARKS.md`**).
- Contributors license their work to everyone under the project license and to the licensor under Apache-2.0, so the project can still be maintained and relicensed later (`CONTRIBUTING.md`).

## Consequences

- ✅ Free for students, researchers, hobbyists and noncommercial organisations worldwide.
- ✅ Selling Redfilade or using it in paid products is not licensed.
- ✅ The license's own "No Liability" clause and the disclaimer state plainly that users are responsible for their use.
- ⚠️ Companies may not use Redfilade, including the GitHub Action in their own CI, so fewer MCP builders can adopt it.
- ⚠️ Some communities, package registries and programmes only accept OSI-approved licenses.
- ⚠️ Copies published before this change stay available under Apache-2.0; that cannot be revoked.
- ⚠️ No license removes liability the law itself imposes. The terms should be reviewed by a lawyer before a public launch.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep Apache-2.0 plus a disclaimer | Allows commercial use and resale, which the maintainer does not want |
| Apache-2.0 with added use restrictions in the license text | Non-standard, legally unclear, and no longer open source anyway |
| Business Source License | Converts to open source after a delay and is built for commercial vendors; not the goal here |

## Revisit when

A commercial offering, a company-friendly tier, or an external contributor community makes the noncommercial restriction a blocker.
