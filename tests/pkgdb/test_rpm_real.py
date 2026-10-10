"""Optional check against a real, large rpmdb.sqlite (skipped when unavailable).

Set ``STARTUP_SBOM_REAL_RPMDB`` to a ``rpmdb.sqlite`` path to run it elsewhere.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from startup_sbom.context import ScanContext, ScanOptions
from startup_sbom.models import OSInfo
from startup_sbom.pkgdb.rpm import RpmDatabase
from startup_sbom.pkgdb.rpm.reader import RpmDB
from startup_sbom.rootfs import DirectoryRootFS

_DEFAULT = (
    "/tmp/claude-1000/-run-media-morpheuslord-Personal-Files-Projects-Startup-SBOM/"
    "57107a66-9fc5-4517-aeb6-b041275d1c28/scratchpad/rpmlab/rpmdb.sqlite"
)
REAL_DB = Path(os.environ.get("STARTUP_SBOM_REAL_RPMDB", _DEFAULT))


@pytest.mark.slow
@pytest.mark.skipif(not REAL_DB.is_file(), reason="real rpmdb.sqlite not available")
def test_real_rpmdb_parses_cleanly():
    fs = DirectoryRootFS(REAL_DB.parent)  # the DB's directory acts as the image root
    ctx = ScanContext(
        fs=fs, options=ScanOptions(offline=True), os=OSInfo(id="fedora", version_id="44")
    )
    reader = RpmDatabase()
    reader.db = RpmDB("/" + REAL_DB.name, "sqlite")
    records = reader.read(ctx)
    assert len(records) > 1000
    assert ctx.warnings == []
    assert len({r.package.id for r in records}) == len(records)
    assert all(r.package.source_name and r.package.version for r in records)
    assert sum(1 for r in records if r.package.signing_key) > len(records) // 2
    assert sum(len(r.files) for r in records) > 10 * len(records)
