"""Go buildinfo, cargo-auditable and Java archive inventories."""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib

from elfbuilder import build_elf, exe

from fsbuilder import File
from startup_sbom.langpkgs import golang, java, rust, scan, scan_binaries
from startup_sbom.pkgdb.ownership import FileOwnerIndex

SENT_A = b"0w\xaf\x0c\x92t\x08\x02A\xe1\xc1\x07\xe6\xd6\x18\xe6"
SENT_B = b"\xf92C1\x86\x18 r\x00\x82B\x10A\x16\xd8\xf2"

MODINFO = (
    "path\tgithub.com/acme/app/cmd/app\n"
    "mod\tgithub.com/acme/app\t(devel)\t\n"
    "dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n"
    "dep\tgithub.com/old/mod\tv1.0.0\th1:x=\n"
    "=>\tgithub.com/new/mod\tv1.2.0\th1:y=\n"
    "dep\texample.com/local\tv0.0.0\n"
    "=>\t../local\t\t\n"
    "build\tCGO_ENABLED=0\n"
    "build\tvcs.revision=deadbeef\n"
    "build\t-ldflags=-X main.secret=dont-keep\n"
)


def _uvarint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def go_blob(version: str = "go1.22.1", modinfo: str = MODINFO) -> bytes:
    mod = SENT_A + modinfo.encode() + SENT_B
    hdr = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16
    return hdr + _uvarint(len(version)) + version.encode() + _uvarint(len(mod)) + mod


def test_parse_inline_buildinfo() -> None:
    bi = golang.parse_buildinfo(b"\x00" * 32 + go_blob())
    assert bi is not None
    assert bi.go_version == "go1.22.1"
    assert bi.path == "github.com/acme/app/cmd/app"
    assert bi.main is not None
    assert bi.main.path == "github.com/acme/app"
    assert [d.path for d in bi.deps] == [
        "golang.org/x/net",
        "github.com/old/mod",
        "example.com/local",
    ]
    assert bi.deps[1].replace is not None
    assert bi.deps[1].replace.version == "v1.2.0"
    assert bi.settings == {"CGO_ENABLED": "0", "vcs.revision": "deadbeef"}


def test_parse_pointer_buildinfo() -> None:
    memory: dict[int, bytes] = {}
    ver, mod = b"go1.16.15", SENT_A + MODINFO.encode() + SENT_B
    memory[0x1000] = struct.pack(">QQ", 0x2000, len(ver))
    memory[0x1100] = struct.pack(">QQ", 0x3000, len(mod))
    memory[0x2000] = ver
    memory[0x3000] = mod

    def read_at(vaddr: int, size: int) -> bytes | None:
        data = memory.get(vaddr)
        return data[:size] if data is not None else None

    blob = b"\xff Go buildinf:" + bytes([8, 1]) + struct.pack(">QQ", 0x1000, 0x1100)
    bi = golang.parse_buildinfo(blob, read_at)
    assert bi is not None
    assert bi.go_version == "go1.16.15"
    assert bi.main is not None
    assert bi.main.path == "github.com/acme/app"
    assert golang.parse_buildinfo(blob) is None  # pointer format needs a reader
    bad = b"\xff Go buildinf:" + bytes([8, 1]) + struct.pack(">QQ", 0x9999, 0x1100)
    assert golang.parse_buildinfo(bad, read_at) is None


def test_malformed_buildinfo() -> None:
    hdr = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16
    assert golang.parse_buildinfo(b"") is None
    assert golang.parse_buildinfo(b"\x00" + go_blob()) is None  # misaligned magic
    assert golang.parse_buildinfo(hdr) is None  # truncated
    assert golang.parse_buildinfo(hdr + b"\xff" * 12) is None  # endless uvarint
    assert golang.parse_buildinfo(hdr + _uvarint(2**40) + b"go") is None  # huge length
    assert golang.parse_buildinfo(go_blob(version="notgo")) is None
    bi = golang.parse_buildinfo(go_blob(modinfo="garbage\tline\nmod\n=>\tx\n"))
    assert bi is not None
    assert bi.main is None
    assert golang.stdlib_version("go1.26.6 X:nocoverageredesign") == "1.26.6"
    assert golang.stdlib_version("devel go1.27-abc") is None


def test_go_binaries_in_root(make_fs, make_ctx) -> None:
    go_elf = build_elf(e_type=2, dynamic=False, sections={".go.buildinfo": go_blob()})
    stripped = build_elf(
        e_type=2, dynamic=False, sections={".go.buildinfo": go_blob()}, section_headers=False
    )
    fs = make_fs(
        {
            "/usr/local/bin/app": File(go_elf, 0o755),
            "/usr/bin/app2": File(go_elf, 0o755),
            "/srv/stripped": File(stripped, 0o755),
            "/usr/bin/cprog": File(exe(), 0o755),
            "/usr/bin/script": File("#!/bin/sh\n" * 10, 0o755),
        }
    )
    idx = FileOwnerIndex(fs)
    idx.add("pkg:deb/debian/app2@1", ["/usr/bin/app2"])
    recs = scan(make_ctx(fs), idx, executables=["/srv/stripped"])
    locs = {r.package.location for r in recs}
    assert locs == {"/usr/local/bin/app", "/usr/bin/app2", "/srv/stripped"}
    app = [r for r in recs if r.package.location == "/usr/local/bin/app"]
    by_name = {r.package.name: r for r in app}
    main = by_name["github.com/acme/app"]
    assert main.package.purl == "pkg:golang/github.com/acme/app"
    assert main.package.version == "(devel)"
    assert main.files == ["/usr/local/bin/app"]
    assert main.package.properties["main_package"] == "github.com/acme/app/cmd/app"
    assert main.package.properties["go.vcs.revision"] == "deadbeef"
    assert "go.-ldflags" not in main.package.properties
    assert by_name["golang.org/x/net"].package.purl == "pkg:golang/golang.org/x/net@v0.17.0"
    new = by_name["github.com/new/mod"].package
    assert (new.version, new.properties["replaces"]) == ("v1.2.0", "github.com/old/mod@v1.0.0")
    local = by_name["example.com/local"].package
    assert local.properties["replaced_by_path"] == "../local"
    assert by_name["stdlib"].package.purl == "pkg:golang/stdlib@1.22.1"
    # the same modules in several binaries get unique, file-qualified ids
    ids = [r.package.id for r in recs]
    assert len(ids) == len(set(ids))
    assert all("file_path=" in r.package.id for r in recs if r.package.name == "golang.org/x/net")
    app2_main = next(
        r for r in recs if r.package.location == "/usr/bin/app2" and r.package.name.endswith("app")
    )
    assert app2_main.package.properties["managed_by"] == "pkg:deb/debian/app2@1"
    # a stripped binary is only searched when it was explicitly requested
    assert not any(r.package.location == "/srv/stripped" for r in scan_binaries(make_ctx(fs), idx))


# --------------------------------------------------------------------------- rust
def dep_v0(packages: list[dict]) -> bytes:
    return zlib.compress(json.dumps({"packages": packages}).encode())


RUST_PKGS = [
    {"name": "myapp", "version": "0.1.0", "source": "local", "dependencies": [1, 2], "root": True},
    {"name": "serde", "version": "1.0.190", "source": "crates.io", "dependencies": [3]},
    {"name": "cc", "version": "1.0.83", "source": "crates.io", "kind": "build"},
    {"name": "serde_derive", "version": "1.0.190", "source": "crates.io"},
    {"name": "std", "version": "1.73.0", "source": "builtin"},
]


def test_cargo_auditable(make_fs, make_ctx) -> None:
    fs = make_fs(
        {
            "/usr/local/bin/myapp": File(build_elf(sections={".dep-v0": dep_v0(RUST_PKGS)}), 0o755),
            "/usr/local/bin/badrust": File(build_elf(sections={".dep-v0": b"notzlib"}), 0o755),
        }
    )
    recs = scan(make_ctx(fs), FileOwnerIndex(fs))
    by_name = {r.package.name: r for r in recs}
    assert sorted(by_name) == ["myapp", "serde", "serde_derive"]
    root = by_name["myapp"]
    assert root.package.purl == "pkg:cargo/myapp@0.1.0"
    assert root.files == ["/usr/local/bin/myapp"]
    assert root.package.depends == ["cc", "serde"]
    assert by_name["serde"].package.properties["source"] == "crates.io"


def test_dep_v0_validation() -> None:
    assert rust.parse_dep_v0(dep_v0(RUST_PKGS)) is not None
    two_roots = [dict(p) for p in RUST_PKGS]
    two_roots[1]["root"] = True
    assert rust.parse_dep_v0(dep_v0(two_roots)) is None
    cycle = [dict(p) for p in RUST_PKGS]
    cycle[3]["dependencies"] = [1]
    assert rust.parse_dep_v0(dep_v0(cycle)) is None
    bad_index = [dict(p) for p in RUST_PKGS]
    bad_index[1]["dependencies"] = [99]
    assert rust.parse_dep_v0(dep_v0(bad_index)) is None
    bad_bool = [dict(p) for p in RUST_PKGS]
    bad_bool[1]["dependencies"] = [True]
    assert rust.parse_dep_v0(dep_v0(bad_bool)) is None
    bad_name = [dict(p) for p in RUST_PKGS]
    bad_name[1]["name"] = "../evil"
    assert rust.parse_dep_v0(dep_v0(bad_name)) is None
    assert rust.parse_dep_v0(zlib.compress(b"[]")) is None
    assert rust.parse_dep_v0(zlib.compress(b'{"packages": []}')) is None
    assert rust.parse_dep_v0(b"\x78\x9c garbage") is None
    bomb = zlib.compress(b" " * (rust.MAX_DECOMPRESSED + 10), 9)
    assert len(bomb) < 100_000
    assert rust.parse_dep_v0(bomb) is None


# --------------------------------------------------------------------------- java
def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _pom(g: str, a: str, v: str) -> bytes:
    return f"#Generated by Maven\ngroupId={g}\nartifactId={a}\nversion={v}\n".encode()


def test_java_archives(make_fs, make_ctx) -> None:
    log4j = _zip({"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties": _pom(
        "org.apache.logging.log4j", "log4j-core", "2.14.1"
    )})  # fmt: skip
    deeper = _zip({"META-INF/maven/x/too-deep/pom.properties": _pom("x", "too-deep", "1")})
    inner = _zip(
        {
            "META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties": _pom(
                "com.fasterxml.jackson.core", "jackson-databind", "2.15.2"
            ),
            "lib/deeper.jar": deeper,
        }
    )
    fat = _zip(
        {
            "META-INF/maven/com.acme/app/pom.properties": _pom("com.acme", "app", "1.0.0"),
            "BOOT-INF/lib/jackson-databind-2.15.2.jar": inner,
            "BOOT-INF/lib/log4j-core-2.14.1.jar": log4j,
        }
    )
    manifest_only = _zip(
        {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nImplementation-Title: foo-lib\n"
            b"Implementation-Version: 1.2\nImplementation-Vendor-Id: org.foo\n\nName: x\n"
        }
    )
    huge_member = _zip({"META-INF/maven/a/b/pom.properties": b"#" * 200_000})
    fs = make_fs(
        {
            "/app/app.jar": fat,
            "/usr/share/java/foo-1.2.jar": manifest_only,
            "/opt/broken.jar": b"PK\x03\x04 not really a zip",
            "/opt/huge.war": huge_member,
            "/opt/readme.txt": "jar",
        }
    )
    idx = FileOwnerIndex(fs)
    idx.add("pkg:deb/debian/libfoo-java@1.2-1", ["/usr/share/java/foo-1.2.jar"])
    recs = java.scan(make_ctx(fs), idx)
    by_name = {r.package.name: r.package for r in recs}
    assert sorted(by_name) == [
        "com.acme:app",
        "com.fasterxml.jackson.core:jackson-databind",
        "org.apache.logging.log4j:log4j-core",
        "org.foo:foo-lib",
    ]
    log = by_name["org.apache.logging.log4j:log4j-core"]
    assert log.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert log.location == (
        "/app/app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar!/"
        "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"
    )
    foo = by_name["org.foo:foo-lib"]
    assert foo.properties["evidence"] == "MANIFEST.MF"
    assert foo.properties["managed_by"] == "pkg:deb/debian/libfoo-java@1.2-1"


def test_java_helpers_and_limits() -> None:
    assert java.parse_properties("! c\n# c\na = 1\nb:2\nc 3\n") == {"a": "1", "b": "2", "c": "3"}
    assert java.parse_manifest("A: x\n y\nB: 2\n\nC: 3\n") == {"A": "xy", "B": "2"}
    assert java.scan_archive(b"", "/x.jar", None) == []
    assert java.scan_archive(b"\x00" * 100, "/x.jar", None) == []
    bomb = _zip({"META-INF/maven/a/b/pom.properties": b"a" * (java.MAX_MEMBER_TEXT + 1)})
    assert java.scan_archive(bomb, "/b.jar", None) == []
