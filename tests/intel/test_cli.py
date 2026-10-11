"""``startup-sbom intel`` CLI: offline lookup against a seeded cache (no sockets)."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from startup_sbom.intel import lookup
from startup_sbom.intel.cli import app
from startup_sbom.net import HttpClient

runner = CliRunner()


@pytest.fixture
def seeded_cache(
    make_http: Callable[..., HttpClient], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """A cache directory holding a real bundle, built through the mock transport."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    cache = tmp_path / "cache"
    lookup("CVE-2024-6387", make_http(cache=cache), articles=False)
    return cache


def test_lookup_offline_renders_sections(seeded_cache: Path) -> None:
    result = runner.invoke(
        app,
        ["lookup", "CVE-2024-6387", "--offline", "--no-articles", "--cache-dir", str(seeded_cache)],
    )
    assert result.exit_code == 0
    out = result.output
    assert "CVE-2024-6387" in out
    assert "Exploitation" in out
    assert "public_poc" in out
    assert "Exploits & PoCs" in out
    assert "USN-6859-1" in out
    assert "Sources:" in out  # attributions are printed


def test_lookup_json_output(seeded_cache: Path) -> None:
    result = runner.invoke(
        app,
        [
            "lookup",
            "CVE-2024-6387",
            "--json",
            "--offline",
            "--no-articles",
            "--cache-dir",
            str(seeded_cache),
        ],
    )
    assert result.exit_code == 0
    (bundle,) = json.loads(result.output)
    assert bundle["cve"] == "CVE-2024-6387"
    assert bundle["exploitation"] == "public_poc"
    assert bundle["poc_repos_count"] == 2


def test_lookup_invalid_cve_fails_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(app, ["lookup", "not-a-cve", "--offline", "--cache-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "error" in result.output


def test_cli_offline_cold_cache_reports_gaps(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["lookup", "CVE-2020-0001", "--offline", "--cache-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert "Data gaps" in result.output
    assert "offline" in result.output
