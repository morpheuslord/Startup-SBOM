"""SafeFetcher guards: the SSRF matrix, caps, robots and redirect re-validation.

Every test runs against a fake DNS resolver and an ``httpx.MockTransport``; no
socket is ever opened and no real DNS lookup happens.
"""

from __future__ import annotations

import ipaddress

import pytest

from intel.helpers import FakeWeb, make_fetcher
from startup_sbom.intel.fetcher import (
    FetchRefusedError,
    SafeFetcher,
    check_url,
    ip_allowed,
    vet_addresses,
)
from startup_sbom.intel.store import IntelStore

# --------------------------------------------------------------------------- URL policy
BAD_URLS = [
    "file:///etc/passwd",
    "ftp://ftp.debian.org/x",
    "gopher://example.org/",
    "https://127.0.0.1/",
    "https://127.1/",
    "https://0x7f000001/",
    "https://[::1]/",
    "https://169.254.169.254/latest/meta-data/",
    "https://10.0.0.1/x",
    "https://user:pw@example.org/",
    "https://example.org:8443/",
    "https://example.org:80/",
    "https://localhost/",
    "https://localhost.localdomain/x",
    "https://metadata.google.internal/",
    "https://instance-data/",
    "https://foo.internal/x",
    "https://router.local/",
    "https://svc.cluster.lan/",
    "https://printer.home.arpa/",
    "https://hidden.onion/",
    "https://unit.test/",
    "https://host.invalid/",
    "https://singlelabel/",
    "https://" + "a" * 260 + ".example.org/",
    "https://exa mple.org/",
]


@pytest.mark.parametrize("url", BAD_URLS)
def test_check_url_refuses(url: str) -> None:
    with pytest.raises(FetchRefusedError):
        check_url(url)


def test_check_url_upgrades_http_and_normalises() -> None:
    url, host = check_url("http://Example.ORG/path?a=1#frag")
    assert url == "https://example.org/path?a=1"
    assert host == "example.org"


def test_check_url_keeps_default_port() -> None:
    url, host = check_url("https://example.org:443/x")
    assert (url, host) == ("https://example.org/x", "example.org")


# --------------------------------------------------------------------------- IP policy
BAD_IPS = [
    "127.0.0.1",  # loopback
    "10.0.0.1",  # RFC 1918
    "172.16.5.5",
    "192.168.1.1",
    "169.254.169.254",  # link-local (cloud metadata)
    "100.64.0.1",  # CGNAT
    "0.0.0.0",  # unspecified  # noqa: S104
    "224.0.0.1",  # multicast
    "240.0.0.1",  # reserved
    "::1",  # v6 loopback
    "fe80::1",  # v6 link-local
    "fc00::1",  # ULA
    "fd12:3456::1",
    "ff02::1",  # v6 multicast
    "::ffff:10.0.0.1",  # IPv4-mapped private
    "::ffff:127.0.0.1",
    "2002:7f00:0001::1",  # 6to4 embedding 127.0.0.1
    "64:ff9b:1::a00:1",  # local-use NAT64
]


@pytest.mark.parametrize("ip", BAD_IPS)
def test_ip_refused(ip: str) -> None:
    assert not ip_allowed(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.216.34", "2606:2800:220:1::1"])
def test_public_ip_allowed(ip: str) -> None:
    assert ip_allowed(ipaddress.ip_address(ip))


def test_vet_addresses_refuses_mixed_answers() -> None:
    """One private A record poisons the whole answer (rebinding via split answers)."""
    with pytest.raises(FetchRefusedError, match="non-public"):
        vet_addresses("evil.example.org", ["93.184.216.34", "10.0.0.1"])
    with pytest.raises(FetchRefusedError):
        vet_addresses("empty.example.org", [])


def test_vet_addresses_prefers_ipv4() -> None:
    assert vet_addresses("x.example.org", ["2606:2800:220:1::1", "93.184.216.34"]) == (
        "93.184.216.34"
    )


# --------------------------------------------------------------------------- DNS + pinning
@pytest.mark.parametrize(
    ("host", "answer"),
    [
        ("localtest.me", ["127.0.0.1"]),
        ("ten.nip.io", ["10.0.0.1"]),
        ("meta.nip.io", ["169.254.169.254"]),
        ("v6loop.example.org", ["::1"]),
        ("ula.example.org", ["fd00::2"]),
    ],
)
def test_fetch_refuses_private_dns_answers(web: FakeWeb, host: str, answer: list[str]) -> None:
    with (
        make_fetcher(web, dns={host: answer}) as fetcher,
        pytest.raises(FetchRefusedError, match="non-public"),
    ):
        fetcher.fetch(f"https://{host}/x")
    assert not web.requests  # refused before anything was sent


def test_fetch_refuses_unresolvable(web: FakeWeb) -> None:
    with make_fetcher(web) as fetcher, pytest.raises(FetchRefusedError, match="DNS failure"):
        fetcher.fetch("https://nxdomain.example.net/")


def test_connection_is_pinned_to_vetted_ip(web: FakeWeb) -> None:
    """The TCP target is the vetted IP; Host and TLS SNI stay on the real hostname."""
    web.add_page("https://example.org/a", "<html><body><p>hi</p></body></html>")
    with make_fetcher(web) as fetcher:
        result = fetcher.fetch("https://example.org/a")
    assert result.status == 200
    assert result.ip == "93.184.216.34"
    for request in web.requests:  # robots.txt and the page itself
        assert request.url.host == "93.184.216.34"  # pinned: no second DNS lookup possible
        assert request.headers["host"] == "example.org"
        assert request.extensions["sni_hostname"] == "example.org"  # TLS verified vs hostname


def test_offline_constructor_refuses() -> None:
    with pytest.raises(FetchRefusedError, match="offline"):
        SafeFetcher(offline=True)


# --------------------------------------------------------------------------- redirects
def test_redirect_to_private_target_refused(web: FakeWeb) -> None:
    web.add_redirect("https://example.org/r", "https://127.0.0.1/")
    web.add_redirect("https://example.org/r2", "http://169.254.169.254/latest/")
    web.add_redirect("https://example.org/r3", "https://internal.example.org/")
    with make_fetcher(web, dns={"internal.example.org": ["10.1.2.3"]}) as fetcher:
        with pytest.raises(FetchRefusedError, match="IP-literal"):
            fetcher.fetch("https://example.org/r")
        with pytest.raises(FetchRefusedError, match="IP-literal"):
            fetcher.fetch("https://example.org/r2")
        with pytest.raises(FetchRefusedError, match="non-public"):
            fetcher.fetch("https://example.org/r3")


def test_redirect_to_non_443_refused(web: FakeWeb) -> None:
    web.add_redirect("https://example.org/r", "https://example.org:8443/x")
    with make_fetcher(web) as fetcher, pytest.raises(FetchRefusedError, match="port"):
        fetcher.fetch("https://example.org/r")


def test_redirect_limit(web: FakeWeb) -> None:
    for i in range(5):
        web.add_redirect(f"https://example.org/{i}", f"https://example.org/{i + 1}")
    with make_fetcher(web) as fetcher, pytest.raises(FetchRefusedError, match="too many"):
        fetcher.fetch("https://example.org/0")


def test_redirect_followed_and_revalidated(web: FakeWeb) -> None:
    web.add_redirect("https://example.org/old", "https://writeups.example.org/new")
    web.add_page("https://writeups.example.org/new", "<p>moved here</p>")
    with make_fetcher(web) as fetcher:
        result = fetcher.fetch("https://example.org/old")
    assert result.status == 200
    assert result.url == "https://writeups.example.org/new"
    assert result.redirects == ["https://writeups.example.org/new"]
    assert result.ip == "93.184.216.35"  # second hop resolved and pinned on its own


# --------------------------------------------------------------------------- caps and types
def test_size_cap_truncates(web: FakeWeb) -> None:
    web.add_page("https://example.org/big", b"<p>" + b"a" * 3000)
    with make_fetcher(web, max_bytes=1024) as fetcher:
        result = fetcher.fetch("https://example.org/big")
    assert result.truncated
    assert result.body is not None
    assert len(result.body) == 1024


def test_content_length_precheck_refuses(web: FakeWeb) -> None:
    web.add_page(
        "https://example.org/huge",
        b"x",
        headers={"content-length": str(50 * 1024 * 1024)},
    )
    with (
        make_fetcher(web, max_bytes=1024) as fetcher,
        pytest.raises(FetchRefusedError, match="content-length"),
    ):
        fetcher.fetch("https://example.org/huge")


def test_content_type_refused(web: FakeWeb) -> None:
    web.add_page("https://example.org/logo.png", b"\x89PNG", content_type="image/png")
    with make_fetcher(web) as fetcher, pytest.raises(FetchRefusedError, match="content-type"):
        fetcher.fetch("https://example.org/logo.png")


def test_pdf_is_metadata_only(web: FakeWeb) -> None:
    web.add_page("https://example.org/paper.pdf", b"%PDF-1.7", content_type="application/pdf")
    with make_fetcher(web) as fetcher:
        result = fetcher.fetch("https://example.org/paper.pdf")
    assert result.status == 200
    assert result.body is None  # never parsed, never stored


def test_bot_wall_recorded_not_retried(web: FakeWeb) -> None:
    web.add_page("https://example.org/blocked", b"", status=403)
    with make_fetcher(web) as fetcher:
        result = fetcher.fetch("https://example.org/blocked")
    assert result.status == 403
    assert result.body is None
    page_hits = [r for r in web.requests if r.url.path == "/blocked"]
    assert len(page_hits) == 1  # one attempt, no retry, no circumvention


# --------------------------------------------------------------------------- robots.txt
def test_robots_wildcard_disallow(web: FakeWeb) -> None:
    """RFC 9309 ``*`` wildcards must be honoured (stdlib robotparser ignores them)."""
    web.robots["example.org"] = "User-agent: *\nDisallow: /*/pulse\nDisallow: /search\n"
    web.add_page("https://example.org/a/pulse", "<p>x</p>")
    web.add_page("https://example.org/search?q=x", "<p>x</p>")
    web.add_page("https://example.org/post", "<p>fine</p>")
    with make_fetcher(web) as fetcher:
        with pytest.raises(FetchRefusedError, match="robots"):
            fetcher.fetch("https://example.org/a/pulse")
        with pytest.raises(FetchRefusedError, match="robots"):
            fetcher.fetch("https://example.org/search?q=x")
        assert fetcher.fetch("https://example.org/post").status == 200


def test_robots_end_anchor(web: FakeWeb) -> None:
    web.robots["example.org"] = "User-agent: *\nDisallow: /*.json$\n"
    web.add_page("https://example.org/data.json", "{}", content_type="application/json")
    web.add_page("https://example.org/data.jsonl", "{}", content_type="application/json")
    with make_fetcher(web) as fetcher:
        with pytest.raises(FetchRefusedError, match="robots"):
            fetcher.fetch("https://example.org/data.json")
        assert fetcher.fetch("https://example.org/data.jsonl").status == 200


def test_robots_missing_allows_5xx_denies(web: FakeWeb) -> None:
    web.robots["example.org"] = 404  # unavailable -> allow (RFC 9309 2.3.1.3)
    web.robots["writeups.example.org"] = 503  # unreachable -> assume disallow
    web.add_page("https://example.org/a", "<p>x</p>")
    web.add_page("https://writeups.example.org/a", "<p>x</p>")
    with make_fetcher(web) as fetcher:
        assert fetcher.fetch("https://example.org/a").status == 200
        with pytest.raises(FetchRefusedError, match="robots"):
            fetcher.fetch("https://writeups.example.org/a")


def test_robots_cached_in_store(web: FakeWeb, store: IntelStore) -> None:
    web.robots["example.org"] = "User-agent: *\nDisallow: /private\n"
    web.add_page("https://example.org/a", "<p>x</p>")
    with make_fetcher(web, store=store) as fetcher:
        fetcher.fetch("https://example.org/a")
    robots_hits = [r for r in web.requests if r.url.path == "/robots.txt"]
    assert len(robots_hits) == 1
    web.requests.clear()
    with make_fetcher(web, store=store) as fetcher:  # new fetcher, same store
        fetcher.fetch("https://example.org/a")
        with pytest.raises(FetchRefusedError, match="robots"):
            fetcher.fetch("https://example.org/private")
    assert not any(r.url.path == "/robots.txt" for r in web.requests)


def test_robots_can_be_disabled_for_tests_only(web: FakeWeb) -> None:
    web.robots["example.org"] = "User-agent: *\nDisallow: /\n"
    web.add_page("https://example.org/x", "<p>x</p>")
    with make_fetcher(web) as fetcher, pytest.raises(FetchRefusedError, match="robots"):
        fetcher.fetch("https://example.org/x")
    with make_fetcher(web, respect_robots=False) as fetcher:
        assert fetcher.fetch("https://example.org/x").status == 200


# --------------------------------------------------------------------------- hygiene
def test_identifying_user_agent_and_no_cookies(web: FakeWeb) -> None:
    web.add_page(
        "https://example.org/a",
        "<p>x</p>",
        headers={"set-cookie": "sid=secret; Path=/"},
    )
    web.add_page("https://example.org/b", "<p>y</p>")
    with make_fetcher(web) as fetcher:
        fetcher.fetch("https://example.org/a")
        fetcher.fetch("https://example.org/b")
    for request in web.requests:
        assert "startup-sbom-intel" in request.headers["user-agent"]
        assert "cookie" not in request.headers
        assert "authorization" not in request.headers
