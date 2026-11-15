# Disclaimer, acceptable use and your responsibility

**Read this before you clone, build or run Redfilade.** By using any part of this repository you accept everything below. If you do not accept it, do not use Redfilade.

This page explains the project's terms in plain language. The binding license is [`LICENSE`](LICENSE) (PolyForm Noncommercial 1.0.0). Where this page and the license differ, the license decides. This page adds conditions on how you use the software; it does not grant you any extra rights.

## 1. What Redfilade is for

Redfilade is a **learning and research range** for the security of the Model Context Protocol (MCP). It exists so people can:

- learn how attacks on MCP servers and clients work, safely, against deliberately vulnerable practice targets;
- discover and document new kinds of attack, so they can be fixed;
- test MCP servers and clients **that they own or are authorised to test**.

It is not a tool for attacking anyone else.

## 2. Acceptable use

You may use Redfilade only:

1. against the practice targets that ship with it, inside its isolation; or
2. against systems, servers, clients, accounts and data that **you own**; or
3. against systems you have **explicit, written permission** to test from the owner, within the scope and time of that permission.

You must not use Redfilade, or anything you learn or build from it, to:

- access, test, scan, disrupt or damage any system you do not own or are not authorised to test;
- steal, expose or destroy data, or collect personal information;
- build or run malware, or attack live services, people or organisations;
- break the law of your country or of the country where a target is located. Examples of such laws are India's Information Technology Act, 2000, the United States' Computer Fraud and Abuse Act and the United Kingdom's Computer Misuse Act 1990. These are examples only, not a complete list.

If you are unsure whether something is allowed, **do not do it**.

## 3. No commercial use

Redfilade is free for personal, educational, research and other **noncommercial** purposes, as defined in the license. **No commercial license is offered.** You may not sell Redfilade, include it in a paid product or service, or use it in work done for a company, unless that company is one of the noncommercial organisations the license names.

## 4. You alone are responsible

- **You are solely responsible** for how you use Redfilade and for everything that results, including any damage, data loss, service disruption, legal claim, fine or penalty.
- The licensor, the maintainers and the contributors **do not take part in, control, approve or know about** how anyone uses copies of this software. **They accept no responsibility or liability** for any use or misuse of Redfilade, of copies or modified versions, or of anything derived from it, by anyone, on any platform, anywhere.
- Publishing an attack technique for learning and defence is **not** permission to use it against anyone.

## 5. No warranty

As far as the law allows, Redfilade comes **as is**, with **no warranty or condition of any kind**: not that it is safe, secure, correct, fit for a purpose, or free of vulnerabilities or malicious code. The licensor will not be liable for any damages arising from the license or from the use or nature of the software, under any kind of legal claim. See the "No Liability" section of [`LICENSE`](LICENSE).

## 6. Verify before you run: we cannot promise this repository is safe

Redfilade deliberately contains **vulnerable code** and **attack code**, and it is a target for attackers in its own right. We work hard to keep it safe: signed commits, protected branches, pinned dependencies, secret scanning and signed releases. Even so, **we cannot promise that this repository, a fork, a mirror, a download or any dependency has not been compromised or made malicious.**

Before you run anything:

- **Get it from the official source only:** `https://github.com/redfilade/redfilade`. Forks and mirrors are not ours.
- **Check that commits are signed** (GitHub shows "Verified") and, for releases, verify the cosign signature and checksums as described in the release notes. Do not run a release you cannot verify.
- **Read the code you are about to run,** especially scripts, workflows and anything new since you last looked.
- **Scan it yourself** with your own tools for known vulnerabilities and malicious code.
- **Run it in a disposable environment:** a virtual machine or a spare computer with no personal data, no credentials, no SSH keys and no access to networks you care about. Never run practice targets on the internet.
- **Treat scenario packs, contributed attacks and target output as hostile.** Run unsigned packs only if you have read them.

If anything looks wrong, stop and [report it privately](SECURITY.md).

## 7. Reporting

- A flaw in Redfilade itself: [private vulnerability reporting](SECURITY.md), never a public issue.
- A flaw you found in someone else's MCP server or client, while testing it with permission: report it privately to its maintainers and give them reasonable time to fix it before you publish anything.

## 8. Name and logo

The Redfilade name and logo are not licensed for your use. See [`TRADEMARKS.md`](TRADEMARKS.md).

## 9. Changes

These terms may be updated. The version in the official repository at the time of your use applies.
