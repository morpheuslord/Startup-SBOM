"""Minimal, bounded LZ4 *frame* decompressor (pure Python).

Ubuntu stores apt package indexes as ``.lz4`` frames, which the standard library
cannot read.  This decoder implements the LZ4 frame and block formats with strict
bounds checks and an output cap; it is used only for such indexes and prefers the
optional ``lz4`` C extension when it is installed.
"""

from __future__ import annotations

import importlib
import struct

FRAME_MAGIC = 0x184D2204
_SKIPPABLE_MIN, _SKIPPABLE_MAX = 0x184D2A50, 0x184D2A5F


class LZ4Error(ValueError):
    """Malformed or oversized LZ4 data."""


def decompress(data: bytes, max_output: int) -> bytes:
    """Decompress concatenated LZ4 frames, refusing to produce more than ``max_output``."""
    try:
        mod = importlib.import_module("lz4.frame")
    except ImportError:
        mod = None
    if mod is not None:  # pragma: no cover - optional accelerator
        out = mod.decompress(data)
        if len(out) > max_output:
            raise LZ4Error("decompressed size exceeds limit")
        return bytes(out)
    return _decompress_py(data, max_output)


def _decompress_py(data: bytes, max_output: int) -> bytes:
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n:
        if n - pos < 4:
            raise LZ4Error("truncated frame header")
        (magic,) = struct.unpack_from("<I", data, pos)
        pos += 4
        if _SKIPPABLE_MIN <= magic <= _SKIPPABLE_MAX:
            if n - pos < 4:
                raise LZ4Error("truncated skippable frame")
            (size,) = struct.unpack_from("<I", data, pos)
            pos += 4 + size
            continue
        if magic != FRAME_MAGIC:
            raise LZ4Error("bad frame magic")
        pos = _frame(data, pos, out, max_output)
    return bytes(out)


def _frame(data: bytes, pos: int, out: bytearray, max_output: int) -> int:
    n = len(data)
    if n - pos < 2:
        raise LZ4Error("truncated frame descriptor")
    flg = data[pos]
    pos += 2  # FLG + BD
    if flg >> 6 != 1:
        raise LZ4Error("unsupported frame version")
    block_checksum = bool(flg & 0x10)
    content_size = bool(flg & 0x08)
    content_checksum = bool(flg & 0x04)
    dict_id = bool(flg & 0x01)
    if dict_id:
        raise LZ4Error("dictionaries are not supported")
    pos += (8 if content_size else 0) + 1  # content size + header checksum
    while True:
        if n - pos < 4:
            raise LZ4Error("truncated block header")
        (size,) = struct.unpack_from("<I", data, pos)
        pos += 4
        if size == 0:
            break
        raw = bool(size & 0x80000000)
        size &= 0x7FFFFFFF
        end = pos + size
        if end > n:
            raise LZ4Error("truncated block")
        if raw:
            out += data[pos:end]
        else:
            _block(data, pos, end, out, max_output)
        if len(out) > max_output:
            raise LZ4Error("decompressed size exceeds limit")
        pos = end + (4 if block_checksum else 0)
    return pos + (4 if content_checksum else 0)


def _block(data: bytes, pos: int, end: int, out: bytearray, max_output: int) -> None:
    """Decode one LZ4 block into ``out`` (history = everything already in ``out``)."""
    while pos < end:
        token = data[pos]
        pos += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if pos >= end:
                    raise LZ4Error("truncated literal length")
                b = data[pos]
                pos += 1
                lit += b
                if b != 255:
                    break
        if pos + lit > end:
            raise LZ4Error("literal run overflows block")
        out += data[pos : pos + lit]
        pos += lit
        if pos >= end:
            return  # last sequence carries literals only
        if pos + 2 > end:
            raise LZ4Error("truncated match offset")
        offset = data[pos] | data[pos + 1] << 8
        pos += 2
        if offset == 0 or offset > len(out):
            raise LZ4Error("invalid match offset")
        mlen = (token & 0x0F) + 4
        if mlen == 19:
            while True:
                if pos >= end:
                    raise LZ4Error("truncated match length")
                b = data[pos]
                pos += 1
                mlen += b
                if b != 255:
                    break
        if len(out) + mlen > max_output:
            raise LZ4Error("decompressed size exceeds limit")
        start = len(out) - offset
        if offset >= mlen:
            out += out[start : start + mlen]
        else:  # overlapping copy: repeat the period
            period = out[start:]
            out += (period * (mlen // offset + 1))[:mlen]
