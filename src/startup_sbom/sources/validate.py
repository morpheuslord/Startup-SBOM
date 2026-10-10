"""Validation and sanitisation of hostile input: references, digests, env, labels.

Container and image references are validated against strict grammars *before*
they reach any subprocess; digests from attacker-controlled JSON are validated
before they become archive member names; environment values are inspected in
memory only to classify their key and are then discarded.
"""

from __future__ import annotations

import re

from startup_sbom.errors import TargetError

MAX_REF_LEN = 512
MAX_NAME_LEN = 255

# moby daemon/names: RestrictedNamePattern = ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$
CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]+$")
# a full 64-hex id or a unique prefix of one
CONTAINER_ID_RE = re.compile(r"^[a-f0-9]{4,64}$")
FULL_ID_RE = re.compile(r"^[a-f0-9]{64}$")
IMAGE_ID_RE = re.compile(r"^sha256:[a-f0-9]{64}$")

# distribution/reference grammar (reference.go)
_ALNUM = r"[a-z0-9]+"
_SEP = r"(?:[._]|__|[-]+)"
_PATH_COMP = rf"{_ALNUM}(?:{_SEP}{_ALNUM})*"
_DOM_COMP = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_DOMAIN = rf"(?:{_DOM_COMP}(?:\.{_DOM_COMP})*|\[[a-fA-F0-9:]+\])(?::[0-9]+)?"
_NAME = rf"(?:{_DOMAIN}/)?{_PATH_COMP}(?:/{_PATH_COMP})*"
_TAG = r"[\w][\w.-]{0,127}"
_DIGEST = r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}"
IMAGE_REF_RE = re.compile(
    rf"^(?P<name>{_NAME})(?::(?P<tag>{_TAG}))?(?:@(?P<digest>{_DIGEST}))?$", re.ASCII
)

# OCI blob digests (validated before building blobs/<alg>/<hex> member names)
BLOB_DIGEST_RE = re.compile(r"^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$")


def is_container_ref(ref: str) -> bool:
    """True if ``ref`` is a syntactically valid container name or id (prefix)."""
    if not ref or len(ref) > MAX_NAME_LEN or ref.startswith("-"):
        return False
    return bool(CONTAINER_ID_RE.match(ref) or CONTAINER_NAME_RE.match(ref))


def is_image_ref(ref: str) -> bool:
    """True if ``ref`` is a valid image reference, image id or id prefix."""
    if not ref or len(ref) > MAX_REF_LEN or ref.startswith("-"):
        return False
    if IMAGE_ID_RE.match(ref) or CONTAINER_ID_RE.match(ref):
        return True
    m = IMAGE_REF_RE.match(ref)
    return bool(m and len(m.group("name")) <= MAX_NAME_LEN)


def validate_container_ref(ref: str) -> str:
    """Return ``ref`` if it is a valid container name/id, else raise :class:`TargetError`."""
    if not is_container_ref(ref):
        raise TargetError(f"invalid container name or id: {ref!r}")
    return ref


def validate_image_ref(ref: str) -> str:
    """Return ``ref`` if it is a valid image reference, else raise :class:`TargetError`."""
    if not is_image_ref(ref):
        raise TargetError(f"invalid image reference: {ref!r}")
    return ref


def blob_name(digest: object) -> str:
    """Map an OCI digest to its ``blobs/<alg>/<hex>`` member name (strictly validated)."""
    if not isinstance(digest, str) or not BLOB_DIGEST_RE.match(digest):
        raise TargetError(f"invalid blob digest {str(digest)[:100]!r}")
    alg, hexd = digest.split(":", 1)
    return f"blobs/{alg}/{hexd}"


# --------------------------------------------------------------------------- text
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def clean(value: object, limit: int = 4096) -> str:
    """Coerce ``value`` to a printable, length-bounded string."""
    text = value if isinstance(value, str) else str(value)
    text = _CTRL_RE.sub("", text)
    return text if len(text) <= limit else text[:limit] + "…"


def sanitize_message(raw: bytes, limit: int = 500) -> str:
    """Decode engine stderr for an error message (control characters removed)."""
    return clean(raw.decode("utf-8", "replace").strip(), limit)


# --------------------------------------------------------------------------- secrets
SECRET_NAME_RE = re.compile(
    r"(PASS(WORD|WD)?|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|"
    r"AUTH(?!OR)|SESSION|COOKIE|DSN|CONN(ECTION)?[_-]?STR|SALT|SIGNING|ENCRYPTION[_-]?KEY|_KEY$|"
    r"^KEY$|CERT[_-]?KEY|WEBHOOK)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = (
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b",  # AWS access key ids
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",  # GitHub tokens
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    r"\bglpat-[A-Za-z0-9_-]{20,}\b",  # GitLab
    r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b",  # Slack
    r"\bsk_live_[A-Za-z0-9]{16,}\b",  # Stripe
    r"\bAIza[0-9A-Za-z_-]{35}\b",  # Google API key
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",  # JWT
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY",  # PEM private keys
    r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@",  # URL with user:pass@
)
SECRET_VALUE_RE = re.compile("|".join(_SECRET_VALUE_PATTERNS))
_ARG_SECRET_RE = re.compile(
    r"(?P<k>(?:--?|\b)[A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*[=:])(?P<v>[^\s'\"]+)",
    re.IGNORECASE,
)
REDACTED = "<redacted>"


def is_secret_name(name: str) -> bool:
    """True if an environment/label key looks like it holds a secret."""
    return bool(SECRET_NAME_RE.search(name))


def looks_like_secret(value: str) -> bool:
    """True if a value matches a well-known credential format."""
    return bool(SECRET_VALUE_RE.search(value))


def split_env(env: object) -> tuple[list[str], list[str]]:
    """Return ``(keys, redacted_keys)`` for a ``["K=V", ...]`` list; values are discarded."""
    keys: set[str] = set()
    redacted: set[str] = set()
    if not isinstance(env, list):
        return [], []
    for item in env[:10_000]:
        if not isinstance(item, str):
            continue
        name, _, value = item.partition("=")
        name = clean(name, 256)
        if not name:
            continue
        keys.add(name)
        if is_secret_name(name) or looks_like_secret(value):
            redacted.add(name)
    return sorted(keys), sorted(redacted)


def redact_text(text: str) -> str:
    """Mask ``--password=x``-style arguments and credential-shaped substrings."""
    text = _ARG_SECRET_RE.sub(lambda m: m.group("k") + REDACTED, text)
    return SECRET_VALUE_RE.sub(REDACTED, text)


def clean_argv(value: object, limit: int = 1000) -> list[str]:
    """Sanitise an Entrypoint/Cmd list (or shell string) with secret arguments masked."""
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [redact_text(clean(v, 8192)) for v in value[:limit] if isinstance(v, str)]


def clean_labels(value: object, limit: int = 1000) -> dict[str, str]:
    """Sanitise a labels mapping; values of secret-looking labels are masked."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in list(value.items())[:limit]:
        if not isinstance(k, str):
            continue
        key = clean(k, 256)
        text = clean(v if isinstance(v, str) else "", 4096)
        out[key] = REDACTED if is_secret_name(key) or looks_like_secret(text) else text
    return dict(sorted(out.items()))


def clean_str_list(value: object, limit: int = 1000) -> list[str]:
    """Sanitise a list of strings (non-strings dropped)."""
    if not isinstance(value, list):
        return []
    return [clean(v, 1024) for v in value[:limit] if isinstance(v, str)]


def opt_str(value: object, limit: int = 1024) -> str | None:
    """Sanitised string or ``None`` for empty/non-string values."""
    if not isinstance(value, str) or not value:
        return None
    return clean(value, limit)
