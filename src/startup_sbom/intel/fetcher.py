"""SafeFetcher: an SSRF-hardened, polite fetcher for *arbitrary* advisory reference URLs.

This is the only component allowed to contact hosts outside the
:mod:`startup_sbom.net` allow-list.  Reference URLs come from third-party advisory
data and are attacker-influenced, so every hop (the first URL and each redirect)
passes, in order:

1. URL policy: HTTPS only (``http://`` refs are upgraded, plaintext is never fetched),
   port 443, no userinfo, no IP literals or numeric hosts, a host deny-list.
2. DNS resolution once per hop; refused if *any* address is not globally routable
   (private, loopback, link-local, CGNAT, multicast, reserved, unspecified, ULA,
   IPv4-mapped/6to4/Teredo embedding such an address).  The vetted address is then
   *pinned*: the TCP connection goes to that IP while TLS SNI, certificate
   verification and the ``Host`` header use the real hostname, so a DNS-rebinding
   second lookup cannot happen.
3. robots.txt (RFC 9309, wildcards via ``protego``) cached for 24 h per host.
4. Per-host politeness delay and a global concurrency cap; identifying User-Agent.
5. Streaming read with a decoded-byte cap and a wall-clock limit, Content-Length
   pre-check, content-type allow-list, no cookies, no proxies, no auth, at most
   three redirects.  403/405/429 are recorded, never retried or circumvented.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from protego import Protego

from startup_sbom.errors import StartupSBOMError

if TYPE_CHECKING:
    from startup_sbom.intel.store import IntelStore

UA = (
    "startup-sbom-intel/2.0 (+https://github.com/morpheuslord/Startup-SBOM; "
    "security-advisory prefetch)"
)
UA_TOKEN = "startup-sbom-intel"  # noqa: S105 - robots.txt product token
ALLOWED_CT = frozenset({"text/html", "application/xhtml+xml", "text/plain", "application/json"})
METADATA_ONLY_CT = frozenset({"application/pdf"})
ROBOTS_CT = frozenset({"text/plain", "text/html", "application/octet-stream", ""})
DENY_HOSTS = frozenset({"metadata.google.internal", "metadata", "localhost", "instance-data"})
DENY_SUFFIXES = (
    ".localhost", ".local", ".internal", ".lan", ".home.arpa", ".onion", ".test",
    ".invalid", ".example", ".intranet", ".corp", ".localdomain", ".in-addr.arpa",
    ".ip6.arpa",
)  # fmt: skip
MAX_BYTES = 2 * 1024 * 1024
ROBOTS_MAX = 512 * 1024
ROBOTS_TTL = 86400.0
MAX_URL = 2048
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")
_HOST_OK = re.compile(r"^[a-z0-9_.-]+$")

Resolver = Callable[[str], list[str]]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class FetchRefusedError(StartupSBOMError):
    """A policy refusal (SSRF guard, robots, size, type), not a transient error."""


@dataclass(slots=True)
class FetchResult:
    url: str  # final URL after redirects
    requested_url: str
    status: int
    content_type: str
    body: bytes | None  # None for non-200 or metadata-only types
    ip: str
    fetched_at: datetime
    redirects: list[str] = field(default_factory=list)
    truncated: bool = False
    charset: str | None = None


# --------------------------------------------------------------------------- policy
def ip_allowed(ip: IPAddress) -> bool:
    """Only globally routable unicast addresses (and nothing embedding a private one)."""
    if isinstance(ip, ipaddress.IPv6Address):
        teredo = ip.teredo
        for embedded in (ip.ipv4_mapped, ip.sixtofour, teredo[1] if teredo else None):
            if embedded is not None and not ip_allowed(embedded):
                return False
        if ip in ipaddress.ip_network("fc00::/7") or ip in ipaddress.ip_network("64:ff9b:1::/48"):
            return False
    if (
        ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_link_local
        or ip.is_loopback
        or ip.is_private
    ):
        return False
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return False
    return ip.is_global


def check_url(url: str) -> tuple[str, str]:
    """Return ``(normalised_url, hostname)`` or raise :class:`FetchRefusedError`."""
    if len(url) > MAX_URL:
        raise FetchRefusedError("URL too long")
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme == "http":  # most NVD refs are http://; try the https twin, never plaintext
        scheme = "https"
    if scheme != "https":
        raise FetchRefusedError(f"scheme {parts.scheme!r} not allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise FetchRefusedError("userinfo in URL")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or len(host) > 253:
        raise FetchRefusedError("bad host")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise FetchRefusedError("IP-literal hosts not allowed")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise FetchRefusedError("bad IDN host") from exc
    if not _HOST_OK.match(ascii_host) or ".." in ascii_host:
        raise FetchRefusedError("bad host")
    labels = ascii_host.split(".")
    if len(labels) < 2 or _NUMERIC_LABEL.match(labels[-1]):
        raise FetchRefusedError(f"host {host!r} denied")
    if ascii_host in DENY_HOSTS or ascii_host.endswith(DENY_SUFFIXES):
        raise FetchRefusedError(f"host {host!r} denied")
    try:
        port = parts.port
    except ValueError as exc:
        raise FetchRefusedError("bad port") from exc
    if port not in (None, 443):
        raise FetchRefusedError("non-default port")
    return urlunsplit(("https", ascii_host, parts.path or "/", parts.query, "")), ascii_host


def system_resolver(host: str) -> list[str]:
    """All addresses ``getaddrinfo`` returns for ``host`` on port 443."""
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]).split("%")[0] for info in infos]


def vet_addresses(host: str, addresses: list[str]) -> str:
    """Return the address to pin, or refuse if any address is non-public."""
    ips: set[IPAddress] = set()
    for raw in addresses:
        try:
            ips.add(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise FetchRefusedError(f"{host}: unparsable address") from exc
    bad = sorted(str(i) for i in ips if not ip_allowed(i))
    if bad or not ips:
        raise FetchRefusedError(f"{host} resolves to non-public address(es) {bad}")
    v4 = sorted(str(i) for i in ips if i.version == 4)
    return v4[0] if v4 else sorted(str(i) for i in ips)[0]


# --------------------------------------------------------------------------- robots
@dataclass(slots=True)
class _Robots:
    mode: str  # "rules" | "allow" | "deny"
    parser: Any = None  # Protego when mode == "rules"
    fetched: float = 0.0

    def can_fetch(self, url: str) -> bool:
        if self.mode == "allow":
            return True
        if self.mode == "deny" or self.parser is None:
            return False
        return bool(self.parser.can_fetch(url, UA_TOKEN))

    def crawl_delay(self) -> float:
        if self.mode != "rules" or self.parser is None:
            return 0.0
        try:
            value = self.parser.crawl_delay(UA_TOKEN)
        except (TypeError, ValueError):
            return 0.0
        return float(value) if value else 0.0


# --------------------------------------------------------------------------- fetcher
class SafeFetcher:
    """Fetch one advisory/article URL at a time under the guards in the module doc."""

    def __init__(
        self,
        *,
        offline: bool = False,
        max_bytes: int = MAX_BYTES,
        max_redirects: int = 3,
        timeout: float = 15.0,
        total_timeout: float = 30.0,
        max_concurrency: int = 4,
        host_delay: float = 1.0,
        respect_robots: bool = True,
        resolver: Resolver | None = None,
        resolve_timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
        store: IntelStore | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if offline:
            raise FetchRefusedError("offline mode: article fetching disabled")
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.total_timeout = total_timeout
        self.host_delay = host_delay
        self.respect_robots = respect_robots
        self._resolver = resolver
        self._resolve_timeout = resolve_timeout
        self._dns_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="intel-dns")
        self._store = store
        self._sleep = sleep
        self._sem = threading.BoundedSemaphore(max(1, max_concurrency))
        self._host_locks: dict[str, threading.Lock] = {}
        self._last_hit: dict[str, float] = {}
        self._robots: dict[str, _Robots] = {}
        self._meta_lock = threading.Lock()
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=min(timeout, 5.0)),
            follow_redirects=False,
            verify=True,
            trust_env=False,  # ignore HTTP(S)_PROXY / .netrc
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
            headers={
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,application/json;q=0.8",
                "Accept-Language": "en",
            },
            limits=httpx.Limits(
                max_connections=max(1, max_concurrency), max_keepalive_connections=0
            ),
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()
        self._dns_pool.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> SafeFetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- DNS ------------------------------------------------------------------
    def resolve(self, host: str) -> str:
        """Resolve ``host`` once and return the vetted address to pin."""
        resolver = self._resolver or system_resolver
        future = self._dns_pool.submit(resolver, host)
        try:
            addresses = future.result(timeout=self._resolve_timeout)
        except FutureTimeout as exc:
            raise FetchRefusedError(f"DNS timeout for {host}") from exc
        except (OSError, UnicodeError) as exc:
            raise FetchRefusedError(f"DNS failure for {host}") from exc
        return vet_addresses(host, list(addresses))

    # -- politeness -----------------------------------------------------------
    def _lock_for(self, host: str) -> threading.Lock:
        with self._meta_lock:
            return self._host_locks.setdefault(host, threading.Lock())

    def _wait_turn(self, host: str, delay: float) -> None:
        last = self._last_hit.get(host)
        if last is not None:
            gap = delay - (time.monotonic() - last)
            if gap > 0:
                self._sleep(gap)
        self._last_hit[host] = time.monotonic()

    # -- one pinned request ---------------------------------------------------
    def _hop(
        self, url: str, host: str, ip: str, *, cap: int, accept: frozenset[str]
    ) -> tuple[httpx.Response, bytes | None, bool]:
        parts = urlsplit(url)
        ip_host = f"[{ip}]" if ":" in ip else ip
        pinned = urlunsplit(("https", ip_host, parts.path or "/", parts.query, ""))
        request = self.client.build_request(
            "GET", pinned, headers={"Host": host}, extensions={"sni_hostname": host}
        )
        started = time.monotonic()
        response = self.client.send(request, stream=True)
        try:
            ctype = _ctype(response)
            if response.is_redirect or response.status_code != 200 or ctype not in accept:
                return response, None, False
            length = response.headers.get("content-length", "")
            if length.isdigit() and int(length) > cap * 4:
                raise FetchRefusedError(f"content-length {length} over cap")
            buf = bytearray()
            truncated = False
            for chunk in response.iter_bytes():  # decoded bytes: bounds gzip bombs too
                buf += chunk
                if len(buf) > cap:
                    truncated = True
                    del buf[cap:]
                    break
                if time.monotonic() - started > self.total_timeout:
                    raise FetchRefusedError("response exceeded the wall-clock limit")
            return response, bytes(buf), truncated
        finally:
            response.close()

    # -- robots ---------------------------------------------------------------
    def _robots_for(self, host: str, ip: str) -> _Robots:
        now = time.time()
        with self._meta_lock:
            hit = self._robots.get(host)
        if hit is not None and now - hit.fetched < ROBOTS_TTL:
            return hit
        robots = self._robots_from_store(host, now)
        if robots is None:
            robots = self._fetch_robots(host, ip, now)
        with self._meta_lock:
            self._robots[host] = robots
        return robots

    def _robots_from_store(self, host: str, now: float) -> _Robots | None:
        if self._store is None:
            return None
        cached = self._store.load_robots(host, ROBOTS_TTL)
        if cached is None:
            return None
        mode, text, fetched = cached
        if mode == "rules":
            return _Robots("rules", Protego.parse(text), fetched)
        return _Robots(mode if mode in ("allow", "deny") else "deny", None, fetched)

    def _fetch_robots(self, host: str, ip: str, now: float) -> _Robots:
        persist = True
        try:
            response, body, _ = self._hop(
                f"https://{host}/robots.txt", host, ip, cap=ROBOTS_MAX, accept=ROBOTS_CT
            )
        except (httpx.HTTPError, FetchRefusedError):
            robots, text, persist = _Robots("deny", None, now), "", False
        else:
            text = ""
            if response.status_code == 200 and body is not None:
                text = body.decode("utf-8", "replace")
                robots = _Robots("rules", Protego.parse(text), now)
            elif response.is_redirect or 400 <= response.status_code < 500:
                robots = _Robots("allow", None, now)  # RFC 9309 2.3.1.3: unavailable
            else:
                robots, persist = _Robots("deny", None, now), False  # 5xx: assume disallow
        if persist and self._store is not None:
            self._store.save_robots(host, robots.mode, text)
        return robots

    # -- public ---------------------------------------------------------------
    def fetch(self, url: str) -> FetchResult:
        """Fetch ``url``; raises :class:`FetchRefusedError` or ``httpx.HTTPError``."""
        requested = url
        url, host = check_url(url)
        redirects: list[str] = []
        with self._sem:
            for _ in range(self.max_redirects + 1):
                ip = self.resolve(host)  # vetted before anything is sent, then pinned
                with self._lock_for(host):
                    robots = self._robots_for(host, ip) if self.respect_robots else None
                    if robots is not None and not robots.can_fetch(url):
                        raise FetchRefusedError(f"robots.txt disallows {url}")
                    delay = max(self.host_delay, robots.crawl_delay() if robots else 0.0)
                    self._wait_turn(host, min(delay, 30.0))
                    response, body, truncated = self._hop(
                        url, host, ip, cap=self.max_bytes, accept=ALLOWED_CT
                    )
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    if not location or len(location) > MAX_URL:
                        raise FetchRefusedError("bad redirect location")
                    url, host = check_url(urljoin(url, location))  # re-validate every hop
                    redirects.append(url)
                    continue
                ctype = _ctype(response)
                if (
                    response.status_code == 200
                    and ctype not in ALLOWED_CT
                    and ctype not in METADATA_ONLY_CT
                ):
                    raise FetchRefusedError(f"content-type {ctype!r} not allowed")
                return FetchResult(
                    url=url,
                    requested_url=requested,
                    status=response.status_code,
                    content_type=ctype,
                    body=body,
                    ip=ip,
                    fetched_at=datetime.now(UTC),
                    redirects=redirects,
                    truncated=truncated,
                    charset=response.charset_encoding,
                )
            raise FetchRefusedError("too many redirects")


def _ctype(response: httpx.Response) -> str:
    value: str = response.headers.get("content-type", "")
    return value.split(";", maxsplit=1)[0].strip().lower()
