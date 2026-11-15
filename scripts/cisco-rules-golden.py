#!/usr/bin/env python3
"""Build the golden corpus that keeps Redfilade's rule engine honest.

Maintainer tool, not run in CI. It needs the reference YARA engine
(yara-python) and the Cisco MCP Scanner repository checked out as data.

  python3 -I scripts/cisco-rules-golden.py RULES_DIR OUT.json SOURCE...

Each SOURCE is either a Python test file, whose string literals are read with
`ast` (the file is never imported or executed), or any other file, whose whole
text is one sample. For every sample the script records which rules the
reference engine matches. `internal/rules` must produce exactly the same set.
"""
import ast
import glob
import json
import os
import re
import sys

import yara


# Fixture values that look like real credentials are replaced before matching,
# so the repository never holds secret-shaped strings (CLAUDE.md). The rules
# are then evaluated on the replaced text, so the golden results stay exact.
SECRET_SHAPED = re.compile(r"(?i)\b((?:[a-z_]*api[_-]?key|[a-z_]*token|[a-z_]*secret|password)\s*[=:]\s*)(?!REDFILADE_TEST_)(?=[A-Za-z_\-]*[0-9])[A-Za-z0-9_\-]{12,}")


def scrub(text):
    return SECRET_SHAPED.sub(lambda m: m.group(1) + "REDFILADE_TEST_KEY_NOT_A_SECRET", text)


def samples(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        src = f.read()
    if not path.endswith(".py"):
        return [src]
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 15:
            out.append(node.value)
    return out


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    rules_dir, out_path, sources = sys.argv[1], sys.argv[2], sys.argv[3:]
    files = sorted(glob.glob(os.path.join(rules_dir, "*.yara")))
    rules = yara.compile(filepaths={os.path.basename(p): p for p in files})
    seen, corpus = set(), []
    for path in sources:
        for text in samples(path):
            text = scrub(text)
            if text in seen:
                continue
            seen.add(text)
            hits = sorted({m.rule for m in rules.match(data=text.encode("utf-8"))})
            corpus.append({"text": text, "rules": hits})
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=1, ensure_ascii=False)
        f.write("\n")
    flagged = sum(1 for c in corpus if c["rules"])
    print(f"{len(corpus)} samples, {flagged} flagged, {len(corpus) - flagged} clean -> {out_path}")


if __name__ == "__main__":
    main()
