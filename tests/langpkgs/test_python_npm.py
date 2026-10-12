"""Python dist-info/egg-info and npm package.json discovery."""

from __future__ import annotations

import json
import sys

import pytest

from fsbuilder import Symlink
from startup_sbom.langpkgs import assign_ids, npm, python, scan
from startup_sbom.langpkgs.python import normalize_name, parse_metadata, sanitize_url
from startup_sbom.pkgdb.ownership import FileOwnerIndex

needs_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="symlinks")

DEB_SITE = "/usr/lib/python3/dist-packages"
VENV_SITE = "/opt/venv/lib/python3.12/site-packages"


def _meta(name: str, version: str | None, extra: str = "") -> str:
    lines = ["Metadata-Version: 2.1", f"Name: {name}"]
    if version is not None:
        lines.append(f"Version: {version}")
    return "\n".join(lines) + "\n" + extra + "\nlong description: here\n"


def _python_spec() -> dict:
    return {
        f"{DEB_SITE}/requests-2.31.0.dist-info/METADATA": _meta(
            "requests",
            "2.31.0",
            "Summary: HTTP for Humans.\nLicense: Apache 2.0\n"
            "Home-page: https://requests.readthedocs.io\n"
            "Requires-Dist: charset_normalizer (<4,>=2)\nRequires-Dist: idna\n"
            "Requires-Dist: PySocks!=1.5.7,>=1.5.6; extra == 'socks'\n",
        ),
        f"{DEB_SITE}/requests-2.31.0.dist-info/INSTALLER": "debian\n",
        f"{DEB_SITE}/requests-2.31.0.dist-info/RECORD": "requests/__init__.py,sha256=x,10\n"
        "requests-2.31.0.dist-info/METADATA,,\n",
        f"{VENV_SITE}/Foo_Bar-1.0.dist-info/METADATA": _meta(
            "Foo_Bar",
            "1.0",
            "License-Expression: MIT\nProject-URL: Homepage, https://foo.example\n",
        ),
        f"{VENV_SITE}/Foo_Bar-1.0.dist-info/RECORD": (
            'foo_bar/__init__.py,sha256=a,1\n"../../../bin/foo",,\n'
        ),
        f"{VENV_SITE}/Foo_Bar-1.0.dist-info/INSTALLER": "uv\n",
        f"{VENV_SITE}/Foo_Bar-1.0.dist-info/direct_url.json": json.dumps(
            {"url": "https://user:s3cr3t@git.example/foo.git?token=x", "vcs_info": {"vcs": "git"}}
        ),
        f"{VENV_SITE}/requests-2.31.0.dist-info/METADATA": _meta("requests", "2.31.0"),
        f"{VENV_SITE}/broken-1.0.dist-info/METADATA": _meta("broken", None),
        f"{VENV_SITE}/garbage-1.0.dist-info/METADATA": b"\xff\xfe\x00\x01" * 10,
        f"{VENV_SITE}/nometa-1.0.dist-info/RECORD": "x,,\n",
        "/usr/local/lib/python3.11/site-packages/legacy-0.1-py3.11.egg-info/PKG-INFO": _meta(
            "Legacy.Pkg", "0.1"
        ),
        "/usr/local/lib/python3.11/site-packages/single.egg-info": _meta("single", "3"),
        "/home/alice/.local/lib/python3.12/site-packages/userpkg-9.dist-info/METADATA": _meta(
            "userpkg", "9"
        ),
        "/opt/app/node_modules/x/site-packages/hidden-1.dist-info/METADATA": _meta("hidden", "1"),
        "/app/.venv/lib/python3.12/site-packages/uvpkg-2.0.dist-info/METADATA": _meta(
            "uvpkg", "2.0"
        ),
        "/app/.git/lib/site-packages/gitpkg-1.dist-info/METADATA": _meta("gitpkg", "1"),
    }


def test_python_distributions(make_fs, make_ctx) -> None:
    fs = make_fs(_python_spec())
    idx = FileOwnerIndex(fs)
    idx.add(
        "pkg:deb/debian/python3-requests@2.31.0+dfsg-1",
        [f"{DEB_SITE}/requests-2.31.0.dist-info/METADATA"],
    )
    recs = python.scan(make_ctx(fs), idx)
    by_loc = {r.package.location: r for r in recs}
    deb = by_loc[f"{DEB_SITE}/requests-2.31.0.dist-info/METADATA"].package
    assert deb.purl == "pkg:pypi/requests@2.31.0"
    assert deb.properties["managed_by"] == "pkg:deb/debian/python3-requests@2.31.0+dfsg-1"
    assert deb.properties["installer"] == "debian"
    assert deb.license == "Apache 2.0"
    assert deb.homepage == "https://requests.readthedocs.io"
    assert deb.summary == "HTTP for Humans."
    assert deb.depends == ["charset-normalizer", "idna"]
    assert deb.file_count == 2
    foo_rec = by_loc[f"{VENV_SITE}/Foo_Bar-1.0.dist-info/METADATA"]
    foo = foo_rec.package
    assert foo.name == "Foo_Bar"
    assert foo.purl == "pkg:pypi/foo-bar@1.0"
    assert foo.license == "MIT"
    assert foo.homepage == "https://foo.example"
    assert "managed_by" not in foo.properties
    assert foo.properties["direct_url"] == "https://git.example/foo.git"
    assert foo.provenance_flags == ["direct_url_install", "vcs_install"]
    assert "/opt/venv/bin/foo" in foo_rec.files
    legacy = by_loc["/usr/local/lib/python3.11/site-packages/legacy-0.1-py3.11.egg-info/PKG-INFO"]
    assert legacy.package.purl == "pkg:pypi/legacy-pkg@0.1"
    assert by_loc["/usr/local/lib/python3.11/site-packages/single.egg-info"].package.version == "3"
    assert any(r.package.name == "userpkg" for r in recs)
    assert any(r.package.name == "uvpkg" for r in recs)
    assert not any(r.package.name in ("broken", "hidden", "gitpkg") for r in recs)


def test_duplicate_purls_get_file_path_qualifier(make_fs, make_ctx) -> None:
    fs = make_fs(_python_spec())
    recs = scan(make_ctx(fs), FileOwnerIndex(fs))
    reqs = [r.package for r in recs if r.package.name == "requests"]
    assert len(reqs) == 2
    assert {p.purl for p in reqs} == {"pkg:pypi/requests@2.31.0"}
    assert all("?file_path=" in p.id for p in reqs)
    assert len({r.package.id for r in recs}) == len(recs)
    foo = next(r.package for r in recs if r.package.name == "Foo_Bar")
    assert foo.id == "pkg:pypi/foo-bar@1.0"
    assert recs == scan(make_ctx(fs), FileOwnerIndex(fs))  # deterministic


def test_metadata_helpers() -> None:
    assert normalize_name("Foo.Bar__baz") == "foo-bar-baz"
    meta = parse_metadata(
        "Name: x\nDescription: a\n  continued\nbad line\nVersion: 1\n\nVersion: 2\n"
    )
    assert meta["description"] == ["a\ncontinued"]
    assert meta["version"] == ["1"]
    assert sanitize_url("https://tok@h.example/p?q=1#f") == "https://h.example/p"
    assert sanitize_url("file:///src/pkg") == "file:///src/pkg"


def _pj(name: str, version: str | None = "1.0.0", **extra: object) -> str:
    doc: dict[str, object] = {"name": name, **extra}
    if version is not None:
        doc["version"] = version
    return json.dumps(doc)


@needs_symlinks
def test_npm_packages(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/lib/node_modules/npm/package.json": _pj("npm", "10.2.0", license="Artistic-2.0"),
            "/usr/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json": _pj(
                "@npmcli/arborist", "7.2.0"
            ),
            "/app/node_modules/express/package.json": _pj(
                "express",
                "4.18.2",
                license={"type": "MIT"},
                repository={"url": "git+https://github.com/expressjs/express.git"},
                dependencies={"accepts": "~1.3.8", "body-parser": "1.20.1"},
                _resolved="https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                _integrity="sha512-abc",
            ),
            "/app/node_modules/express/test/fixtures/package.json": _pj("fixture-pkg"),
            "/app/node_modules/@types/node/package.json": _pj("@types/node", "20.0.0"),
            "/app/node_modules/bad/package.json": "{not json",
            "/app/node_modules/noversion/package.json": _pj("noversion", None),
            "/app/node_modules/array/package.json": "[1, 2]",
            "/app/test/fixtures/node_modules/evil/package.json": _pj("evil"),
            "/srv/web/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json": _pj(
                "lodash", "4.17.21"
            ),
            "/srv/web/node_modules/lodash": Symlink(".pnpm/lodash@4.17.21/node_modules/lodash"),
        }
    )
    recs = npm.scan(make_ctx(fs), FileOwnerIndex(fs))
    by_name = {r.package.name: r.package for r in recs}
    assert sorted(by_name) == ["@npmcli/arborist", "@types/node", "express", "lodash", "npm"]
    assert by_name["@types/node"].purl == "pkg:npm/%40types/node@20.0.0"
    exp = by_name["express"]
    assert exp.license == "MIT"
    assert exp.homepage == "git+https://github.com/expressjs/express.git"
    assert exp.depends == ["accepts", "body-parser"]
    assert exp.properties["integrity"] == "sha512-abc"
    assert by_name["@npmcli/arborist"].properties["nesting"] == "1"
    assert by_name["npm"].license == "Artistic-2.0"
    assert sum(1 for r in recs if r.package.name == "lodash") == 1


def test_assign_ids_drops_same_location_duplicates(make_fs, make_ctx) -> None:
    fs = make_fs({"/app/node_modules/a/package.json": _pj("a")})
    recs = npm.scan(make_ctx(fs), FileOwnerIndex(fs))
    out = assign_ids(recs + npm.scan(make_ctx(fs), FileOwnerIndex(fs)))
    assert [r.package.id for r in out] == ["pkg:npm/a@1.0.0"]


def test_disabled_and_failure_isolation(make_fs, make_ctx, monkeypatch) -> None:
    fs = make_fs(_python_spec() | {"/app/node_modules/a/package.json": _pj("a")})
    assert scan(make_ctx(fs, language_packages=False), FileOwnerIndex(fs)) == []

    def boom(*_a: object, **_k: object) -> list:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(python, "scan", boom)
    ctx = make_ctx(fs)
    recs = scan(ctx, FileOwnerIndex(fs))
    assert [r.package.name for r in recs] == ["a"]
    assert any("python package scan failed" in w for w in ctx.warnings)
