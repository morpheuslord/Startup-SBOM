"""net.py allow-list: hosts, path prefixes for shared code hosts, host-bound credentials."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from startup_sbom.errors import NetworkError
from startup_sbom.net import ALLOWED_HOSTS, HttpClient, auth_headers, url_allowed

MSF_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/"
    "modules_metadata_base.json"
)
POC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-6387.json"
EDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"


# --------------------------------------------------------------------------- url_allowed
@pytest.mark.parametrize(
    "url",
    [
        "https://api.osv.dev/v1/querybatch",
        "https://cveawg.mitre.org/api/cve/CVE-2024-6387",
        "https://ubuntu.com/security/cves/CVE-2024-6387.json",
        "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-6387.json",
        "https://api.github.com/advisories?cve_id=CVE-2024-6387",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6387",
        MSF_URL,
        POC_URL,
        "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
        EDB_URL,
    ],
)
def test_url_allowed(url: str) -> None:
    assert url_allowed(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://api.osv.dev/v1/querybatch",  # not https
        "https://api.osv.dev:8443/v1/querybatch",  # non-default port
        "https://user@api.osv.dev/v1/querybatch",  # userinfo
        "https://evil.example.com/",  # unknown host
        "https://api.osv.dev.evil.example.com/",  # suffix spoof
        "https://raw.githubusercontent.com/attacker/repo/main/payload.json",  # wrong repo
        "https://raw.githubusercontent.com/",  # no path
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/../evil/x.json",
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/%2e%2e/x.json",
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master\\evil",
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/masterX/2024/x.json",
        "https://gitlab.com/attacker/exploitdb/-/raw/main/files_exploits.csv",
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv/extra",
    ],
)
def test_url_refused(url: str) -> None:
    assert not url_allowed(url)


def test_prefix_dir_vs_exact_file() -> None:
    # directory prefixes admit children; file entries are exact matches only
    assert url_allowed(POC_URL)
    assert url_allowed(
        "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/a.json"
    )
    assert not url_allowed(MSF_URL + ".evil")


# --------------------------------------------------------------------------- auth headers
def test_auth_headers_bound_to_their_hosts() -> None:
    env = {"GITHUB_TOKEN": "ghp_test", "NVD_API_KEY": "nvd_test"}
    assert auth_headers("https://api.github.com/advisories", env) == {
        "Authorization": "Bearer ghp_test"
    }
    assert auth_headers("https://services.nvd.nist.gov/rest/json/cves/2.0", env) == {
        "apiKey": "nvd_test"
    }
    # the binding is per host: nothing leaks to any other host, allow-listed or not
    for url in ("https://ubuntu.com/security/x.json", MSF_URL, "https://evil.example.com/"):
        assert auth_headers(url, env) == {}
    assert auth_headers("https://api.github.com/advisories", {"GITHUB_TOKEN": "  "}) == {}
    assert auth_headers("https://api.github.com/advisories", {}) == {}


def _client(tmp_path: Path, handler: httpx.MockTransport) -> HttpClient:
    return HttpClient(cache_dir=tmp_path, retries=0, transport=handler)


def test_client_refuses_credential_header_to_wrong_host(tmp_path: Path) -> None:
    transport = httpx.MockTransport(lambda _r: httpx.Response(200, json={}))
    with _client(tmp_path, transport) as http:
        with pytest.raises(NetworkError, match="credential header"):
            http.get("https://ubuntu.com/x.json", headers={"Authorization": "Bearer leak"})
        with pytest.raises(NetworkError, match="credential header"):
            http.get(MSF_URL, headers={"authorization": "Bearer leak"})  # case-insensitive
        with pytest.raises(NetworkError, match="credential header"):
            http.get("https://cveawg.mitre.org/api/cve/x", headers={"apiKey": "leak"})
        # bound hosts still accept their own credential
        resp = http.get("https://api.github.com/advisories", headers={"Authorization": "Bearer t"})
        assert resp.status == 200


def test_client_enforces_allow_list(tmp_path: Path) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    with _client(tmp_path, httpx.MockTransport(handler)) as http:
        assert http.get(POC_URL).json() == {"ok": True}
        with pytest.raises(NetworkError, match="non-allow-listed"):
            http.get("https://raw.githubusercontent.com/attacker/repo/main/x.json")
        with pytest.raises(NetworkError, match="non-allow-listed"):
            http.get("http://api.osv.dev/v1/query")
    assert seen == [POC_URL]  # the refused URLs never reached the transport


def test_allow_list_is_closed_over_expected_hosts() -> None:
    # intel's structured feeds are present; nothing generic (github.com, pypi, ...) is
    assert {"cveawg.mitre.org", "ubuntu.com", "access.redhat.com", "api.github.com"} <= set(
        ALLOWED_HOSTS
    )
    assert "github.com" not in ALLOWED_HOSTS
    assert "raw.githubusercontent.com" not in ALLOWED_HOSTS  # path-prefixed, not blanket
    assert "gitlab.com" not in ALLOWED_HOSTS
