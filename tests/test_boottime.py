"""Boot timing parsers for systemd-analyze blame text and plot SVG."""

from __future__ import annotations

from pathlib import Path

import pytest

from startup_sbom.boottime import (
    MAX_INPUT_BYTES,
    load_boot_timing,
    parse_blame,
    parse_plot_svg,
    parse_timespan,
)
from startup_sbom.errors import ParseError

BLAME = """\
1min 30.123s plymouth-quit-wait.service
      6.042s NetworkManager-wait-online.service
      1.137s dev-nvme0n1p2.device
       812ms systemd-journal-flush.service
       503ms user@1000.service
        90ms systemd-fsck@dev-disk-by\\x2duuid-1234.service
       2h 3min 4s weird.timer
       517us tiny.mount
Startup finished in 3.1s (kernel) + 9.8s (userspace) = 12.9s
not a line
"""

PLOT = """<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="1300px" height="2000px" version="1.1" xmlns="http://www.w3.org/2000/svg">
<text x="20" y="50">Startup finished in 3.120s (kernel) + 9.811s (userspace) = 12.932s</text>
<text x="20" y="30">myhost (Linux 6.9.0) #1 SMP x86-64 KVM debian</text>
  <rect class="activating" x="230.000" y="300.000" width="10.000" height="19.000" />
  <text class="left" x="235.000" y="314.000">systemd-journald.service (123ms)</text>
  <text class="right" x="900.000" y="334.000">NetworkManager-wait-online.service (6.042s)</text>
  <text class="left" x="235.000" y="354.000">plymouth-quit-wait.service (1min 2.3s)</text>
  <text class="left" x="235.000" y="374.000">a&amp;b.service (5ms)</text>
  <text class="left" x="235.000" y="394.000">dev-sda.device</text>
  <text class="left" x="235.000" y="414.000">two.service (1.5s / 2.0s)</text>
  <text class="left" x="235.000" y="434.000">&lt;script&gt;x (1s)</text>
</svg>
"""


def test_timespan() -> None:
    assert parse_timespan("123ms") == 123
    assert parse_timespan("1.234s") == 1234
    assert parse_timespan("1min 2.3s") == pytest.approx(62300)
    assert parse_timespan("2h 3min 4s") == pytest.approx(7_384_000)
    assert parse_timespan("517us") == pytest.approx(0.517)
    assert parse_timespan("kernel") is None
    assert parse_timespan("") is None


def test_parse_blame() -> None:
    got = parse_blame(BLAME)
    assert got["plymouth-quit-wait.service"] == pytest.approx(90123)
    assert got["NetworkManager-wait-online.service"] == 6042
    assert got["dev-nvme0n1p2.device"] == 1137
    assert got["user@1000.service"] == 503
    assert got["systemd-fsck@dev-disk-by\\x2duuid-1234.service"] == 90
    assert got["weird.timer"] == pytest.approx(7_384_000)
    assert got["tiny.mount"] == pytest.approx(0.517)
    assert len(got) == 8


def test_parse_plot_svg() -> None:
    got = parse_plot_svg(PLOT)
    assert got == {
        "systemd-journald.service": 123,
        "NetworkManager-wait-online.service": 6042,
        "plymouth-quit-wait.service": pytest.approx(62300),
        "two.service": 1500,
    }


def test_load_detects_format(tmp_path: Path) -> None:
    svg = tmp_path / "plot.svg"
    svg.write_text(PLOT)
    txt = tmp_path / "blame.txt"
    txt.write_text(BLAME)
    assert "systemd-journald.service" in load_boot_timing(svg)
    assert "dev-nvme0n1p2.device" in load_boot_timing(txt)


def test_load_limits_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ParseError):
        load_boot_timing(tmp_path / "missing.svg")
    monkeypatch.setattr("startup_sbom.boottime.MAX_INPUT_BYTES", 100)
    big = tmp_path / "big.txt"
    big.write_text("x" * 200)
    with pytest.raises(ParseError, match="exceeds"):
        load_boot_timing(big)
    assert MAX_INPUT_BYTES > 100


def test_hostile_svg_is_text_only() -> None:
    evil = (
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">'
        '<!ENTITY a "&x;&x;&x;">]><svg><text>&x; (1s)</text>'
        "<text>ok.service (2s)</text></svg>"
    )
    assert parse_plot_svg(evil) == {"ok.service": 2000}
    assert parse_plot_svg("<text>" + "a" * 100_000 + " (1s)</text>") == {}
