"""Live progress: pipeline activity events, stage digests, the CLI dashboard and journal."""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console

from fsbuilder import File, Symlink, build_dir
from startup_sbom.context import ScanOptions
from startup_sbom.dashboard import ScanDashboard
from startup_sbom.digest import services_digest, threats_digest, vulns_digest
from startup_sbom.pipeline import ActivityEvent, ProgressEvent, scan

DPKG_STATUS = """\
Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2

Package: openssh-server
Status: install ok installed
Architecture: amd64
Version: 1:9.2p1-2
"""

ROOT = {
    "/etc/os-release": 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n',
    "/var/lib/dpkg/status": DPKG_STATUS,
    "/var/lib/dpkg/info/openssh-server.list": "/usr/sbin/sshd\n",
    "/usr/sbin/sshd": File(b"\x7fELF\x02\x01\x01" + b"\x00" * 9, mode=0o755),
    "/usr/lib/systemd/systemd": File(b"\x7fELF\x02\x01\x01" + b"\x00" * 9, mode=0o755),
    "/sbin/init": Symlink("/usr/lib/systemd/systemd"),
    "/usr/lib/systemd/system/ssh.service": (
        "[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\n"
    ),
    "/etc/systemd/system/multi-user.target.wants/ssh.service": Symlink(
        "/usr/lib/systemd/system/ssh.service"
    ),
}


def _scan(tmp_path: Path) -> tuple[list[ProgressEvent], list[ActivityEvent]]:
    root = build_dir(tmp_path / "root", ROOT)
    progress: list[ProgressEvent] = []
    activity: list[ActivityEvent] = []
    scan(
        f"dir:{root}",
        ScanOptions(offline=True, vuln_sources=(), eol=False, language_packages=False),
        progress=progress.append,
        activity=activity.append,
    )
    return progress, activity


def test_every_stage_reports_a_digest_and_operations(tmp_path: Path) -> None:
    progress, activity = _scan(tmp_path)
    digests = {e.stage: e for e in activity if e.kind == "digest"}
    stages = [p.stage for p in progress]
    for stage in stages:
        if stage != "Explaining results":
            assert stage in digests, stage
    assert "2 OS packages from dpkg" in digests["Reading package databases"].message
    assert digests["Reading package databases"].data["packages"] == 2
    ops = [e.message for e in activity if e.kind == "op"]
    assert any(m.startswith("dpkg: 2 installed package") for m in ops)
    assert any(m.startswith("systemd:") for m in ops)


def test_ops_do_not_leak_to_the_log_while_captured(tmp_path: Path, caplog: object) -> None:
    import logging

    from startup_sbom.log import ops

    _scan(tmp_path)
    assert ops.propagate  # restored after the scan
    assert ops.level == logging.NOTSET


def test_no_activity_sink_costs_nothing(tmp_path: Path) -> None:
    root = build_dir(tmp_path / "root", ROOT)
    report = scan(f"dir:{root}", ScanOptions(offline=True, vuln_sources=(), eol=False))
    assert report.summary.packages >= 2


def test_dashboard_plain_mode_and_journal(tmp_path: Path) -> None:
    out = io.StringIO()
    console = Console(file=out, force_terminal=False, width=200)
    journal = tmp_path / "scan.jsonl"
    with ScanDashboard("dir:/x", console, journal=journal) as board:
        board.progress(ProgressEvent("Reading package databases", 1, 2))
        board.activity(ActivityEvent("Reading package databases", "op", "dpkg: 2 read"))
        board.activity(
            ActivityEvent("Reading package databases", "digest", "2 OS packages", {"n": 2})
        )
        board.activity(ActivityEvent("x", "op", "evil " + chr(0x1B) + "[31m text"))
    text = out.getvalue()
    assert "[1/2] Reading package databases" in text
    assert "digest: 2 OS packages" in text
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    assert [r["kind"] for r in rows] == ["stage", "op", "digest", "op"]
    assert rows[2]["data"] == {"n": 2}


def test_dashboard_live_render_is_sanitised() -> None:
    out = io.StringIO()
    console = Console(file=out, force_terminal=True, width=120, color_system=None)
    board = ScanDashboard("dir:/x", console, analyst="test-model")
    board.progress(ProgressEvent("Stage", 1, 1))
    board.activity(ActivityEvent("Stage", "op", "evil \x1b[31m text"))
    console.print(board)
    rendered = out.getvalue()
    assert "raw operations (1)" in rendered
    assert "live analyst" in rendered
    assert "\x1b[31m text" not in rendered


def test_digests_handle_empty_inputs() -> None:
    assert "no actionable" in threats_digest([])[0]
    msg, _data = vulns_digest([])
    assert msg.startswith("0 vulnerabilities")
    assert services_digest([])[1]["services"] == 0


def test_journal_is_owner_only_and_sanitised(tmp_path: Path) -> None:
    import stat
    import sys

    journal = tmp_path / "scan.jsonl"
    journal.write_text("old")
    journal.chmod(0o644)
    out = io.StringIO()
    with ScanDashboard("dir:/x", Console(file=out), journal=journal, display="none") as board:
        board.activity(ActivityEvent("s", "op", "bad " + chr(0x1B) + "[2J" + chr(0x202E) + "x"))
    assert out.getvalue() == ""  # display none draws nothing
    row = json.loads(journal.read_text())
    assert chr(0x1B) not in row["message"]
    assert chr(0x202E) not in row["message"]
    if sys.platform != "win32":
        assert stat.S_IMODE(journal.stat().st_mode) == 0o600


def test_warnings_reach_the_activity_stream() -> None:
    from startup_sbom.context import ScanContext
    from startup_sbom.rootfs import DirectoryRootFS

    seen: list[str] = []
    ctx = ScanContext(fs=DirectoryRootFS("."), on_warning=seen.append)
    ctx.warn("dpkg: database could not be read")
    assert seen == ["dpkg: database could not be read"]
    assert ctx.warnings == seen


def test_quiet_with_journal_draws_nothing(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from startup_sbom import cli

    root = build_dir(tmp_path / "root", ROOT)
    journal = tmp_path / "j.jsonl"
    result = CliRunner().invoke(
        cli.app,
        ["scan", f"dir:{root}", "--offline", "--sources", "none", "--no-eol", "-q",
         "--journal", str(journal)],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert result.output == ""
    assert journal.read_text().count('"kind": "digest"') >= 3
