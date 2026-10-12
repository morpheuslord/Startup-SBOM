"""Make the synthetic ELF writer importable as ``elfbuilder``."""

from __future__ import annotations

import sys
from pathlib import Path

_here = str(Path(__file__).parent)
if _here not in sys.path:
    sys.path.insert(0, _here)
