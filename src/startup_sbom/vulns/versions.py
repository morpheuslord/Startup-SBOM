"""Native version ordering for every package ecosystem we match locally.

Pure-Python ports of the reference algorithms, so results are identical to the
distribution tooling:

* ``deb``  -- dpkg ``verrevcmp`` (``~`` sorts before everything, epochs, revisions).
* ``rpm``  -- ``rpmvercmp`` incl. ``~`` (pre-release) and ``^`` (post-release),
  compared as ``epoch:version-release``.
* ``apk``  -- apk-tools ``apk_version_compare`` (``_alpha < _beta < _pre < _rc <
  release < _cvs < _svn < _git < _hg < _p``, ``-rN`` revisions).
* ``alpm`` -- pacman ``alpm_pkg_vercmp`` (``1.0a < 1.0 < 1.0.a < 1.0.1``).
* language ecosystems -- PEP 440 for PyPI, a SemVer-like ordering otherwise.

:func:`compare` returns a negative number, zero or a positive number like ``cmp``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import cmp_to_key
from itertools import zip_longest

from startup_sbom.models import PackageType

_DIGITS = frozenset("0123456789")
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ALNUM = _DIGITS | _ALPHA


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


# --------------------------------------------------------------------------- dpkg
def _dpkg_order(c: str) -> int:
    if c in _DIGITS:
        return 0
    if c in _ALPHA:
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and a[i] not in _DIGITS) or (j < lb and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i]) if i < la else 0
            bc = _dpkg_order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i] in _DIGITS and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i] in _DIGITS:
            return 1
        if j < lb and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_epoch(v: str) -> tuple[int, str]:
    head, sep, tail = v.partition(":")
    if sep and head.isdigit():
        return int(head), tail
    return 0, v


def parse_dpkg(v: str) -> tuple[int, str, str]:
    """Split a Debian version into ``(epoch, upstream, revision)``."""
    epoch, rest = _split_epoch(v.strip())
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        return epoch, rest, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    """Compare two Debian versions exactly like ``dpkg --compare-versions``."""
    ea, ua, ra = parse_dpkg(a)
    eb, ub, rb = parse_dpkg(b)
    if ea != eb:
        return _sign(ea - eb)
    return _sign(_verrevcmp(ua, ub)) or _sign(_verrevcmp(ra, rb))


# --------------------------------------------------------------------------- rpm
def rpmvercmp(a: str, b: str) -> int:
    """librpm ``rpmvercmp`` on a version *or* release string (no epoch)."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and a[i] not in _ALNUM and a[i] not in "~^":
            i += 1
        while j < lb and b[j] not in _ALNUM and b[j] not in "~^":
            j += 1
        a_t = i < la and a[i] == "~"
        b_t = j < lb and b[j] == "~"
        if a_t or b_t:
            if not a_t:
                return 1
            if not b_t:
                return -1
            i += 1
            j += 1
            continue
        a_c = i < la and a[i] == "^"
        b_c = j < lb and b[j] == "^"
        if a_c or b_c:
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if not a_c:
                return 1
            if not b_c:
                return -1
            i += 1
            j += 1
            continue
        if not (i < la and j < lb):
            break
        si, sj = i, j
        isnum = a[i] in _DIGITS
        cls = _DIGITS if isnum else _ALPHA
        while i < la and a[i] in cls:
            i += 1
        while j < lb and b[j] in cls:
            j += 1
        seg1, seg2 = a[si:i], b[sj:j]
        if not seg2:
            return 1 if isnum else -1
        if isnum:
            seg1 = seg1.lstrip("0")
            seg2 = seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return 1 if seg1 > seg2 else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def parse_evr(v: str) -> tuple[int, str, str | None]:
    """Split ``[epoch:]version[-release]`` into its parts (release may be ``None``)."""
    epoch, rest = _split_epoch(v.strip())
    version, sep, release = rest.rpartition("-")
    if not sep:
        return epoch, rest, None
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int:
    """Compare two RPM ``[epoch:]version-release`` strings (``rpmdev-vercmp``)."""
    ea, va, ra = parse_evr(a)
    eb, vb, rb = parse_evr(b)
    if ea != eb:
        return _sign(ea - eb)
    rc = rpmvercmp(va, vb)
    if rc:
        return rc
    if ra is None and rb is None:
        return 0
    if rb is None:
        return 1
    if ra is None:
        return -1
    return rpmvercmp(ra, rb)


# --------------------------------------------------------------------------- pacman
def _alpm_rpmvercmp(a: str, b: str) -> int:
    """pacman's variant of rpmvercmp (separator length matters, alpha tails are older)."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la and j < lb:
        p1, p2 = i, j
        while i < la and a[i] not in _ALNUM:
            i += 1
        while j < lb and b[j] not in _ALNUM:
            j += 1
        if not (i < la and j < lb):
            break
        if (i - p1) != (j - p2):
            return -1 if (i - p1) < (j - p2) else 1
        si, sj = i, j
        isnum = a[i] in _DIGITS
        cls = _DIGITS if isnum else _ALPHA
        while i < la and a[i] in cls:
            i += 1
        while j < lb and b[j] in cls:
            j += 1
        seg1, seg2 = a[si:i], b[sj:j]
        if not seg2:
            return 1 if isnum else -1
        if isnum:
            seg1 = seg1.lstrip("0")
            seg2 = seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return 1 if seg1 > seg2 else -1
    if i >= la and j >= lb:
        return 0
    one_alpha = i < la and a[i] in _ALPHA
    two_alpha = j < lb and b[j] in _ALPHA
    if (i >= la and not two_alpha) or one_alpha:
        return -1
    return 1


def alpm_compare(a: str, b: str) -> int:
    """Compare two pacman ``[epoch:]pkgver[-pkgrel]`` strings like ``vercmp(8)``."""
    if a == b:
        return 0
    ea, va, ra = parse_evr(a)
    eb, vb, rb = parse_evr(b)
    if ea != eb:
        return _sign(ea - eb)
    rc = _alpm_rpmvercmp(va, vb)
    if rc == 0 and ra is not None and rb is not None:
        rc = _alpm_rpmvercmp(ra, rb)
    return rc


# --------------------------------------------------------------------------- apk
_T_INVALID, _T_DIGIT_OR_ZERO, _T_DIGIT, _T_LETTER, _T_SUFFIX, _T_SUFFIX_NO = -1, 0, 1, 2, 3, 4
_T_REVISION_NO, _T_END = 5, 6
_APK_PRE = ("alpha", "beta", "pre", "rc")
_APK_POST = ("cvs", "svn", "git", "hg", "p")


class _ApkTokens:
    """Tokeniser state for one apk version string (port of apk-tools ``version.c``)."""

    __slots__ = ("pos", "s", "type")

    def __init__(self, s: str) -> None:
        self.s = s
        self.pos = 0
        self.type = _T_DIGIT

    def _next_token(self) -> None:
        s, p, cur = self.s, self.pos, self.type
        n = _T_INVALID
        if p >= len(s):
            n = _T_END
        elif cur in (_T_DIGIT, _T_DIGIT_OR_ZERO) and s[p].islower() and s[p].isascii():
            n = _T_LETTER
        elif cur == _T_LETTER and s[p] in _DIGITS:
            n = _T_DIGIT
        elif cur == _T_SUFFIX and s[p] in _DIGITS:
            n = _T_SUFFIX_NO
        else:
            c = s[p]
            if c == ".":
                n = _T_DIGIT_OR_ZERO
            elif c == "_":
                n = _T_SUFFIX
            elif c == "-" and p + 1 < len(s) and s[p + 1] == "r":
                n = _T_REVISION_NO
                p += 1
            p += 1
        if n < cur and not (
            (n == _T_DIGIT_OR_ZERO and cur == _T_DIGIT)
            or (n == _T_SUFFIX and cur == _T_SUFFIX_NO)
            or (n == _T_DIGIT and cur == _T_LETTER)
        ):
            n = _T_INVALID
        self.pos = p
        self.type = n

    def get(self) -> int:
        s, p = self.s, self.pos
        if p >= len(s):
            self.type = _T_END
            return 0
        v = 0
        i = 0
        nt = _T_INVALID
        rest = s[p:]
        t = self.type
        if t == _T_DIGIT_OR_ZERO and rest[0] == "0":
            # leading zeros: the run (minus one) is a negative token, the last zero
            # is then read again as an ordinary digit token
            while i + 1 < len(rest) and rest[i + 1] == "0":
                i += 1
            nt = _T_DIGIT
            v = -i
        elif t in (_T_DIGIT_OR_ZERO, _T_DIGIT, _T_SUFFIX_NO, _T_REVISION_NO):
            while i < len(rest) and rest[i] in _DIGITS:
                v = v * 10 + ord(rest[i]) - 48
                i += 1
            if i >= 18:
                self.type = _T_INVALID
                return -1
        elif t == _T_LETTER:
            v = ord(rest[0])
            i = 1
        elif t == _T_SUFFIX:
            for idx, suf in enumerate(_APK_PRE):
                if rest.startswith(suf):
                    v, i = idx - len(_APK_PRE), len(suf)
                    break
            else:
                for idx, suf in enumerate(_APK_POST):
                    if rest.startswith(suf):
                        v, i = idx, len(suf)
                        break
                else:
                    self.type = _T_INVALID
                    return -1
        else:
            self.type = _T_INVALID
            return -1
        self.pos = p + i
        if self.pos >= len(s):
            self.type = _T_END
        elif nt != _T_INVALID:
            self.type = nt
        else:
            self._next_token()
        return v


def apk_compare(a: str, b: str) -> int:
    """Compare two Alpine ``pkgver-rN`` versions like ``apk version -t``."""
    ta, tb = _ApkTokens(a.strip()), _ApkTokens(b.strip())
    av = bv = 0
    while ta.type == tb.type and ta.type not in (_T_END, _T_INVALID) and av == bv:
        av = ta.get()
        bv = tb.get()
    if av != bv:
        return -1 if av < bv else 1
    if ta.type == tb.type:
        return 0
    if ta.type == _T_SUFFIX and _peek_suffix(ta) < 0:
        return -1
    if tb.type == _T_SUFFIX and _peek_suffix(tb) < 0:
        return 1
    if ta.type > tb.type:
        return -1
    if tb.type > ta.type:
        return 1
    return 0


def _peek_suffix(tok: _ApkTokens) -> int:
    copy = _ApkTokens(tok.s)
    copy.pos, copy.type = tok.pos, tok.type
    return copy.get()


# --------------------------------------------------------------------------- PEP 440
_PEP440 = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>\d+)?)?
    (?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_NORM = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "pre": "rc"}
_PRE_NORM |= {"preview": "rc", "rc": "rc"}
_PRE_RANK = {"a": 0.0, "b": 1.0, "rc": 2.0}
_INF = float("inf")

_Pep440Key = tuple[int, tuple[int, ...], tuple[float, ...], tuple[float, ...], tuple[float, ...]]


def _pep440_key(v: str) -> tuple[_Pep440Key, tuple[tuple[int, int | str], ...]] | None:
    m = _PEP440.match(v)
    if m is None:
        return None
    release = tuple(int(x) for x in m["release"].split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre: tuple[float, ...]
    post: tuple[float, ...]
    dev: tuple[float, ...]
    if m["pre_l"]:
        pre = (_PRE_RANK[_PRE_NORM[m["pre_l"].lower()]], float(m["pre_n"] or 0))
    elif m["dev_l"] and not (m["post_n1"] or m["post_l"]):
        pre = (-_INF,)
    else:
        pre = (_INF,)
    has_post = bool(m["post_n1"] or m["post_l"])
    post = (float(m["post_n1"] or m["post_n2"] or 0),) if has_post else (-_INF,)
    dev = (float(m["dev_n"] or 0),) if m["dev_l"] else (_INF,)
    local: tuple[tuple[int, int | str], ...] = ()
    if m["local"]:
        local = tuple(
            (1, int(p)) if p.isdigit() else (0, p.lower()) for p in re.split(r"[-_.]", m["local"])
        )
    return (int(m["epoch"] or 0), release, pre, post, dev), local


def pep440_compare(a: str, b: str) -> int:
    """PEP 440 ordering; falls back to :func:`semver_compare` for non-PEP 440 strings."""
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return semver_compare(a, b)
    if ka[0] != kb[0]:
        return -1 if ka[0] < kb[0] else 1
    la, lb = ka[1], kb[1]
    if la == lb:
        return 0
    return -1 if la < lb else 1


# --------------------------------------------------------------------------- SemVer-ish
def _ident_cmp(x: str, y: str) -> int:
    xd, yd = x.isdigit(), y.isdigit()
    if xd and yd:
        return _sign(int(x) - int(y))
    if xd != yd:
        return -1 if xd else 1
    return (x > y) - (x < y)


def semver_compare(a: str, b: str) -> int:
    """SemVer 2.0 precedence, tolerant of ``v`` prefixes, extra/missing components and
    Maven/Go-style strings (numeric components compare numerically)."""

    def split(v: str) -> tuple[list[str], list[str] | None]:
        v = v.strip()
        if v[:1] in ("v", "V") and v[1:2].isdigit():
            v = v[1:]
        v = v.split("+", 1)[0]
        main, sep, pre = v.partition("-")
        parts = [p for p in re.split(r"[.]", main) if p != ""]
        return parts, (pre.split(".") if sep else None)

    ma, pa = split(a)
    mb, pb = split(b)
    for x, y in zip_longest(ma, mb, fillvalue="0"):
        rc = _ident_cmp(x, y)
        if rc:
            return rc
    if pa is None and pb is None:
        return 0
    if pa is None:
        return 1
    if pb is None:
        return -1
    for i in range(max(len(pa), len(pb))):
        if i >= len(pa):
            return -1
        if i >= len(pb):
            return 1
        rc = _ident_cmp(pa[i], pb[i])
        if rc:
            return rc
    return 0


# --------------------------------------------------------------------------- dispatch
_COMPARATORS = {
    PackageType.DEB: dpkg_compare,
    PackageType.RPM: rpm_compare,
    PackageType.APK: apk_compare,
    PackageType.ALPM: alpm_compare,
    PackageType.PYPI: pep440_compare,
}

_ECOSYSTEM_TYPES: dict[str, PackageType] = {
    "Debian": PackageType.DEB,
    "Ubuntu": PackageType.DEB,
    "Echo": PackageType.DEB,
    "Alpine": PackageType.APK,
    "Wolfi": PackageType.APK,
    "Chainguard": PackageType.APK,
    "MinimOS": PackageType.APK,
    "Alpaquita": PackageType.APK,
    "BellSoft Hardened Containers": PackageType.APK,
    "Red Hat": PackageType.RPM,
    "Rocky Linux": PackageType.RPM,
    "AlmaLinux": PackageType.RPM,
    "SUSE": PackageType.RPM,
    "openSUSE": PackageType.RPM,
    "openEuler": PackageType.RPM,
    "Azure Linux": PackageType.RPM,
    "Mageia": PackageType.RPM,
    "Photon OS": PackageType.RPM,
    "PyPI": PackageType.PYPI,
    "npm": PackageType.NPM,
    "Go": PackageType.GOLANG,
    "Maven": PackageType.MAVEN,
    "crates.io": PackageType.CARGO,
}
_TUXCARE_TYPES = {
    "Debian": PackageType.DEB,
    "Ubuntu": PackageType.DEB,
}


def ecosystem_package_type(ecosystem: str) -> PackageType | None:
    """Package type whose version ordering an OSV ecosystem string uses (``None`` = unknown)."""
    parts = ecosystem.split(":")
    if parts[0] == "TuxCare":
        if len(parts) > 1 and parts[1] in _ECOSYSTEM_TYPES and parts[1] in _TUXCARE_TYPES:
            return _TUXCARE_TYPES[parts[1]]
        return PackageType.RPM if len(parts) > 1 else None
    return _ECOSYSTEM_TYPES.get(parts[0])


def compare(ptype: PackageType, a: str, b: str) -> int:
    """Compare versions ``a`` and ``b`` with the native ordering of ``ptype``.

    Returns ``-1``, ``0`` or ``1``.  Never raises on malformed input.
    """
    fn = _COMPARATORS.get(ptype, semver_compare)
    return _sign(fn(a, b))


def sort_versions(ptype: PackageType, versions: list[str]) -> list[str]:
    """Sort and de-duplicate ``versions`` ascending in the native order of ``ptype``."""

    def cmp(x: str, y: str) -> int:
        return compare(ptype, x, y)

    return sorted(sorted(set(versions)), key=cmp_to_key(cmp))


# --------------------------------------------------------------------------- derivatives
def strip_derivative_suffix(version: str, vendors: Iterable[str]) -> str:
    """Drop a derivative's own revision marker from a dpkg ``version``.

    Rolling Debian derivatives rebuild Debian packages under a vendor suffix
    (``1.2.3-1+kali1``, ``2.4-0kali2``, ``5.1-2parrot1``); to be compared against
    the parent's advisory ranges the suffix is removed (``1.2.3-1``, ``2.4-0``).

    Conservative by construction: the result is returned only if it sorts *at or
    below* ``version`` in dpkg order, so a package can only look less patched,
    never more.  ``1.2.3-1~kali1`` (which sorts *before* ``1.2.3-1``) is therefore
    kept as is -- dpkg ordering already places it below Debian's ``1.2.3-1``.
    """
    names = sorted({v.lower() for v in vendors if v and v.isascii()}, key=len, reverse=True)
    if not names:
        return version
    alts = "|".join(re.escape(n) for n in names)
    m = re.search(rf"[+.~]?(?:{alts})[0-9.]*(?:\+b\d+)?$", version, re.IGNORECASE)
    if m is None:
        return version
    stripped = version[: m.start()].rstrip("-")
    if not stripped or stripped.endswith(":") or dpkg_compare(stripped, version) > 0:
        return version
    return stripped
