## What and why

<!-- What does this change, and why is it needed? Link the issue or ADR. -->

## Security checklist

- [ ] No secrets, tokens or real credentials (including in tests and docs)
- [ ] No new dependency, **or** the new dependency is justified below (age, maintainers, size, install scripts)
- [ ] Any new GitHub Action is pinned to a full commit SHA, with the version in a comment
- [ ] No new workflow permission, **or** it is explained in a comment next to it
- [ ] Untrusted input (tool output, scenario data, report text) is never executed or rendered as HTML
- [ ] Commits are signed and signed off (`git commit -s`)

## New dependencies

<!-- Delete if none. -->
