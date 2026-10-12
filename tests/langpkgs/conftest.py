"""Make the synthetic ELF writer from ``tests/binaries`` importable as ``elfbuilder``."""

from __future__ import annotations

import sys
from pathlib import Path

_bin = str(Path(__file__).parent.parent / "binaries")
if _bin not in sys.path:
    sys.path.insert(0, _bin)
