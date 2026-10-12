"""OpenPGP signature packet decoding for RPM signature tags (RFC 4880 / RFC 9580).

``RSAHEADER``, ``DSAHEADER``, ``SIGPGP`` and ``SIGGPG`` each hold one signature
packet; rpm 6's ``OPENPGP`` tag holds base64 packets.  Only the issuer key id,
issuer fingerprint, algorithms and creation time are extracted.  Malformed
input yields ``None``.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Iterator
from dataclasses import dataclass

HASH_ALGOS: dict[int, str] = {
    1: "md5",
    2: "sha1",
    3: "ripemd160",
    8: "sha256",
    9: "sha384",
    10: "sha512",
    11: "sha224",
    12: "sha3-256",
    14: "sha3-512",
}
PUBKEY_ALGOS: dict[int, str] = {
    1: "RSA",
    2: "RSA",
    3: "RSA",
    16: "ElGamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    22: "EdDSA",
    25: "X25519",
    26: "X448",
    27: "Ed25519",
    28: "Ed448",
}
_SIG_PACKET_TAG = 2
_SUB_CREATED, _SUB_ISSUER, _SUB_ISSUER_FPR = 2, 16, 33


class _MalformedError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class PgpSignature:
    """Summary of one OpenPGP signature packet."""

    version: int
    pubkey_algo: str
    hash_algo: str
    created: int | None
    key_id: str | None  # 16 lowercase hex digits
    fingerprint: str | None  # 40 (v4) or 64 (v6) hex digits when present

    def summary(self) -> str:
        """Text like ``rpm -q --qf '%{RSAHEADER:pgpsig}'``."""
        when = "?"
        if self.created:
            when = time.strftime("%a %b %e %H:%M:%S %Y", time.gmtime(self.created))
        return f"{self.pubkey_algo}/{self.hash_algo.upper()}, {when}, Key ID {self.key_id}"


def _take(buf: bytes, pos: int, n: int) -> bytes:
    if n < 0 or pos < 0 or pos + n > len(buf):
        raise _MalformedError
    return buf[pos : pos + n]


def _packet_body(raw: bytes) -> tuple[int, bytes]:
    if not raw or not raw[0] & 0x80:
        raise _MalformedError
    head = raw[0]
    if head & 0x40:  # new format
        tag = head & 0x3F
        l0 = _take(raw, 1, 1)[0]
        if l0 < 192:
            length, pos = l0, 2
        elif l0 < 224:
            length, pos = ((l0 - 192) << 8) + _take(raw, 2, 1)[0] + 192, 3
        elif l0 == 255:
            length, pos = struct.unpack(">I", _take(raw, 2, 4))[0], 6
        else:
            raise _MalformedError  # partial body lengths: never used for signatures
    else:  # old format
        tag = (head >> 2) & 0x0F
        ltype = head & 3
        if ltype == 0:
            length, pos = _take(raw, 1, 1)[0], 2
        elif ltype == 1:
            length, pos = struct.unpack(">H", _take(raw, 1, 2))[0], 3
        elif ltype == 2:
            length, pos = struct.unpack(">I", _take(raw, 1, 4))[0], 5
        else:
            length, pos = len(raw) - 1, 1
    return tag, _take(raw, pos, length)


def _subpackets(data: bytes) -> Iterator[tuple[int, bytes]]:
    i = 0
    while i < len(data):
        l0 = data[i]
        if l0 < 192:
            length, i = l0, i + 1
        elif l0 < 255:
            length, i = ((l0 - 192) << 8) + _take(data, i + 1, 1)[0] + 192, i + 2
        else:
            length, i = struct.unpack(">I", _take(data, i + 1, 4))[0], i + 5
        if length == 0:
            return
        body = _take(data, i, length)
        yield body[0] & 0x7F, body[1:]
        i += length


def _parse(raw: bytes) -> PgpSignature:
    tag, body = _packet_body(raw)
    if tag != _SIG_PACKET_TAG:
        raise _MalformedError
    ver = _take(body, 0, 1)[0]
    if ver in (2, 3):
        # ver, hashed-len(5), sigtype, created(4), keyid(8), pubalgo, hashalgo
        fixed = _take(body, 0, 17)
        v3_created = struct.unpack_from(">I", fixed, 3)[0]
        return PgpSignature(
            ver,
            PUBKEY_ALGOS.get(fixed[15], str(fixed[15])),
            HASH_ALGOS.get(fixed[16], str(fixed[16])),
            v3_created or None,
            fixed[7:15].hex(),
            None,
        )
    if ver not in (4, 5, 6):
        raise _MalformedError
    pk, ha = _take(body, 2, 2)
    fmt, lsz = (">I", 4) if ver in (5, 6) else (">H", 2)
    pos = 4
    hlen = struct.unpack(fmt, _take(body, pos, lsz))[0]
    pos += lsz
    hashed = _take(body, pos, hlen)
    pos += hlen
    ulen = struct.unpack(fmt, _take(body, pos, lsz))[0]
    pos += lsz
    unhashed = _take(body, pos, ulen)
    created: int | None = None
    key_id: str | None = None
    fpr: str | None = None
    for area in (hashed, unhashed):
        for stype, sdata in _subpackets(area):
            if stype == _SUB_CREATED and len(sdata) >= 4:
                created = created or struct.unpack(">I", sdata[:4])[0]
            elif stype == _SUB_ISSUER and len(sdata) == 8:
                key_id = key_id or sdata.hex()
            elif stype == _SUB_ISSUER_FPR and len(sdata) >= 21:
                fpr = fpr or sdata[1:].hex()
    if key_id is None and fpr:
        # v4 key id = low 64 bits of the fingerprint; v6 = high 64 bits
        key_id = fpr[-16:] if len(fpr) == 40 else fpr[:16]
    return PgpSignature(
        ver, PUBKEY_ALGOS.get(pk, str(pk)), HASH_ALGOS.get(ha, str(ha)), created, key_id, fpr
    )


def parse_signature(raw: bytes) -> PgpSignature | None:
    """Decode one OpenPGP signature packet; ``None`` if it is malformed."""
    try:
        return _parse(raw)
    except (_MalformedError, struct.error, IndexError, ValueError):
        return None
