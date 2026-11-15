# Architecture Decision Records

Each significant decision is recorded as one short page: the question, the options, the choice, and what we gave up. Product names are current choices, not lock-in; each record says when to revisit it.

To propose a change, copy [`template.md`](template.md) to the next number and open a pull request.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-isolate-attack-runs-in-microvms.md) | Isolate attack runs in microVMs | Accepted |
| [0002](0002-schedule-runs-and-isolate-tenants-with-kubernetes.md) | Schedule runs and isolate tenants with Kubernetes | Accepted |
| [0003](0003-languages-go-core-python-harness-typescript-web.md) | Languages: Go core, Python harness, TypeScript web | Accepted |
| [0004](0004-postgres-for-results-write-once-object-storage-for-evidence.md) | Postgres for results, write-once object storage for evidence | Accepted |
| [0005](0005-postgres-job-table-before-any-message-broker.md) | Postgres job table before any message broker | Accepted |
| [0006](0006-the-oracle-observes-from-the-host-side-with-ebpf.md) | The oracle observes from the host side with eBPF | Accepted |
| [0007](0007-keyless-signing-of-results-and-releases.md) | Keyless signing of results and releases | Accepted |
| [0008](0008-a-thin-fully-reviewable-model-proxy.md) | A thin, fully reviewable model proxy | Accepted |
| [0009](0009-sign-in-through-github-oauth-and-enterprise-sso.md) | Sign-in through GitHub OAuth and enterprise SSO | Accepted |
| [0010](0010-remote-testing-only-against-verified-domains.md) | Remote testing only against verified domains | Accepted |
| [0011](0011-standard-report-formats.md) | Standard report formats | Accepted |
| [0012](0012-supported-mcp-protocol-versions.md) | Supported MCP protocol versions | Accepted |
| [0013](0013-scenario-format.md) | Scenarios are data, judged by facts | Accepted |
| [0014](0014-synthetic-org-and-canaries.md) | A fresh synthetic organisation with random canaries for every run | Accepted |
| [0015](0015-local-isolation-and-consent.md) | Local isolation tiers and a consent gate | Accepted |
| [0016](0016-scenario-packs-and-triage-lane.md) | Signed scenario packs and an isolated triage lane | Accepted |
| [0017](0017-source-available-noncommercial-license.md) | Source-available license: noncommercial or internal use | Accepted |
| [0018](0018-reuse-cisco-mcp-scanner-rules.md) | Reuse Cisco MCP Scanner's detection rules with our own engine | Accepted |
| [0019](0019-http-transport-and-remote-testing.md) | Streamable HTTP transport and testing servers by URL | Accepted |
| [0020](0020-domain-proofs-and-address-pinning.md) | Domain proofs, live re-checks and address pinning for remote tests | Accepted |
| [0021](0021-l3-agent-in-the-loop.md) | L3 agent-in-the-loop scenarios | Accepted |
| [0022](0022-hosted-test-bench-mvp.md) | Hosted Test Bench, first version | Accepted |
| [0023](0023-l4-hostile-server-client-testing.md) | L4: testing MCP clients with a hostile server | Accepted |
