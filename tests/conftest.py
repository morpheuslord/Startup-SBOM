"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fsbuilder import Spec, build_dir, build_tar  # noqa: E402

from startup_sbom.context import ScanContext, ScanOptions  # noqa: E402
from startup_sbom.rootfs import DirectoryRootFS, LayerBlob, LayeredTarRootFS, RootFS  # noqa: E402


@pytest.fixture
def make_dir_fs(tmp_path: Path) -> Callable[[Spec], DirectoryRootFS]:
    """Build a directory-backed RootFS from a spec."""
    counter = iter(range(1_000_000))

    def _make(spec: Spec) -> DirectoryRootFS:
        return DirectoryRootFS(build_dir(tmp_path / f"root{next(counter)}", spec))

    return _make


@pytest.fixture
def make_tar_fs(tmp_path: Path) -> Callable[..., LayeredTarRootFS]:
    """Build a layered tar RootFS from one or more specs (lowest layer first)."""
    counter = iter(range(1_000_000))

    def _make(*specs: Spec) -> LayeredTarRootFS:
        blobs = [
            LayerBlob(str(build_tar(tmp_path / f"layer{next(counter)}.tar", s))) for s in specs
        ]
        return LayeredTarRootFS(blobs)

    return _make


@pytest.fixture(params=["dir", "tar"])
def make_fs(
    request: pytest.FixtureRequest,
    make_dir_fs: Callable[[Spec], DirectoryRootFS],
    make_tar_fs: Callable[..., LayeredTarRootFS],
) -> Callable[[Spec], RootFS]:
    """Parametrised: the same spec through both backends."""
    if request.param == "dir":
        return make_dir_fs
    return lambda spec: make_tar_fs(spec)


@pytest.fixture
def make_ctx() -> Callable[..., ScanContext]:
    def _make(fs: RootFS, **options: object) -> ScanContext:
        return ScanContext(fs=fs, options=ScanOptions(offline=True, **options))  # type: ignore[arg-type]

    return _make
