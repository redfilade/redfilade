# Cisco MCP Scanner detection rules (third party)

The `*.yara` files in this directory are copied **unmodified** from
[cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner),
directory `mcpscanner/data/yara_rules/`, at commit
`9ff8fc84b792aae315a838cf4e37b40ef46a0293`.

- Copyright 2025 Cisco Systems, Inc. and its affiliates.
- Licensed under the Apache License, Version 2.0 (see `LICENSE` in this
  directory). These files, and the test fixtures in `testdata/` taken from the
  same repository's `tests/test_yara_rules_coverage.py` and
  `tests/test_yara_analyzer.py`, stay under Apache-2.0; Redfilade's own
  licenses do not apply to them.
- Cisco does not endorse Redfilade.

`SHA256SUMS` pins the exact bytes. To update, copy the new files, refresh
`SHA256SUMS` and the commit above, regenerate `testdata/` with
`scripts/cisco-rules-golden.py`, and review every rule change by hand.
