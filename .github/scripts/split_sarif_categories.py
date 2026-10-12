"""Give every run in a multi-tool SARIF file its own code-scanning category.

The Codacy Analysis CLI writes one run per tool into a single SARIF file.
Code scanning rejects several runs under one category, so each run gets an
``automationDetails.id`` of ``<prefix>-<tool>/``.  Artifact URIs are also
percent-encoded (Codacy emits raw spaces, which are not valid URIs).

Usage: split_sarif_categories.py IN.sarif OUT.sarif PREFIX
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "tool"


def _encode_uris(node: Any) -> Any:
    if isinstance(node, dict):
        return {
            key: quote(value, safe="/:%#?&=@+~")
            if key == "uri" and isinstance(value, str)
            else _encode_uris(value)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [_encode_uris(item) for item in node]
    return node


def main(src: str, dst: str, prefix: str) -> int:
    sarif = json.loads(Path(src).read_text(encoding="utf-8"))
    seen: dict[str, int] = {}
    for run in sarif.get("runs", []):
        slug = _slug(run.get("tool", {}).get("driver", {}).get("name", ""))
        seen[slug] = seen.get(slug, 0) + 1
        suffix = "" if seen[slug] == 1 else f"-{seen[slug]}"
        run["automationDetails"] = {"id": f"{prefix}-{slug}{suffix}/"}
    Path(dst).write_text(json.dumps(_encode_uris(sarif)), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
