"""Turn failed test cases in a JUnit XML report into GitHub Actions annotations.

Job logs require a signed-in viewer; annotations are shown on the run summary
and inline on pull requests, so failures stay readable for everyone.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

MAX_ANNOTATIONS = 20
MAX_LINES = 25


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: str) -> str:
    return _escape(value).replace(":", "%3A").replace(",", "%2C")


def main(path: str) -> int:
    root = ET.parse(path).getroot()  # noqa: S314
    emitted = 0
    for case in root.iter("testcase"):
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        if problem is None:
            continue
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        detail = (problem.text or problem.get("message") or "").strip().splitlines()
        body = "\n".join(detail[-MAX_LINES:])
        sys.stdout.write(f"::error title={_escape_property(test_id)}::{_escape(body)}\n")
        emitted += 1
        if emitted >= MAX_ANNOTATIONS:
            sys.stdout.write(f"::warning::more than {MAX_ANNOTATIONS} failures; see the log\n")
            break
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
