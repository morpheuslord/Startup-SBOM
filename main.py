"""Deprecated 1.x entry point, kept so existing scripts keep working.

Prefer the installed command::

    startup-sbom scan dir:/mnt/target_root -f json -f cyclonedx

This shim maps the old flags (--volume-path, --docker, --save-file, ...) onto the
2.x scanner.  Run it with `uv run main.py ...` or after `pip install .`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from startup_sbom.legacy import main

if __name__ == "__main__":
    main()
