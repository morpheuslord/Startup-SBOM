"""Declared network listeners of well-known daemons, from their configuration files.

Covers OpenSSH ``sshd_config`` (``Port``/``ListenAddress``, ``Include``; default
port 22 on all addresses), nginx ``listen`` (``include`` globs; a ``server``
block without ``listen`` defaults to ``*:80``) and Apache ``Listen``
(``Include``/``IncludeOptional``).  Command-line overrides (``sshd -p/-f``,
``nginx -c``, ``httpd -f``) are honoured.  Regex-level, bounded, root-confined.

Also hosts the small service-finishing helpers shared by the non-systemd
analyzers (:func:`finish_service`, :func:`base_hardening`).
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Callable

from startup_sbom.initsys.cmdline import Resolution, fs_glob
from startup_sbom.initsys.systemd.hardening import SecurityInput, to_hardening
from startup_sbom.models import Command, Hardening, ListenAddress, Service
from startup_sbom.rootfs import RootFS

CONFIG_LIMIT = 1024 * 1024
MAX_FILES = 200
MAX_DEPTH = 10

Listener = Callable[[RootFS, list[str]], tuple[list[ListenAddress], list[str]]]


def _scope(host: str | None) -> str:
    if host is None or host in ("*", "0.0.0.0", "::", ""):  # noqa: S104 - classification only
        return "network"
    if host == "localhost":
        return "loopback"
    try:
        return "loopback" if ipaddress.ip_address(host.strip("[]")).is_loopback else "network"
    except ValueError:
        return "network"


def _norm_host(host: str | None) -> str | None:
    if host in (None, "", "*"):
        return None
    return host.strip("[]") if host else None


def split_host_port(value: str) -> tuple[str | None, int | None]:
    """Split ``host:port``, ``[v6]:port``, ``port`` or ``host`` (port ``None`` if absent)."""
    v = value.strip()
    if v.isdigit():
        return None, int(v)
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", v)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else None
    if v.count(":") == 1:
        host, _, port = v.partition(":")
        return host, int(port) if port.isdigit() else None
    return v, None


def _arg(argv: list[str], flag: str) -> list[str]:
    out: list[str] = []
    for i, a in enumerate(argv):
        if a == flag and i + 1 < len(argv):
            out.append(argv[i + 1])
        elif a.startswith(flag) and len(a) > len(flag) and not a.startswith("--"):
            out.append(a[len(flag) :])
    return out


def _mk(proto: str, host: str | None, port: int | None, source: str) -> ListenAddress:
    return ListenAddress(
        protocol=proto, address=_norm_host(host), port=port, scope=_scope(host), source=source
    )


# --------------------------------------------------------------------------- sshd
def sshd_listens(fs: RootFS, argv: list[str]) -> tuple[list[ListenAddress], list[str]]:
    """Listeners of OpenSSH ``sshd`` (none in inetd mode ``-i``)."""
    if "-i" in argv[1:]:
        return [], []
    config = (_arg(argv[1:], "-f") or ["/etc/ssh/sshd_config"])[-1]
    ports: list[int] = []
    addrs: list[str] = []
    evidence: list[str] = []
    files = 0

    def parse(path: str, depth: int) -> bool:
        nonlocal files
        files += 1
        if depth > MAX_DEPTH or files > MAX_FILES:
            return False
        text = fs.try_read_text(path, CONFIG_LIMIT)
        if text is None:
            return False
        evidence.append(path)
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$", line)
            if not m:
                continue
            key, value = m.group(1).lower(), m.group(2).strip()
            if key == "match":
                return True
            if key == "include":
                for pat in value.split():
                    for inc in fs_glob(fs, pat, cwd="/etc/ssh"):
                        if parse(inc, depth + 1):
                            return True
            elif key == "port":
                for tok in value.split():
                    if tok.isdigit() and int(tok) <= 65535:
                        ports.append(int(tok))
            elif key == "listenaddress" and value:
                addrs.append(value.split()[0])
        return False

    parse(config, 0)
    for spec in ("-p",):
        cli = [int(p) for p in _arg(argv[1:], spec) if p.isdigit()]
        if cli:
            ports = cli
    for opt in _arg(argv[1:], "-o"):
        k, _, v = opt.partition("=")
        if k.strip().lower() == "port" and v.strip().isdigit():
            ports.append(int(v.strip()))
    source = config
    if not ports:
        ports = [22]
        source = f"{config} (default Port 22)"
    out: list[ListenAddress] = []
    if not addrs:
        out = [_mk("tcp", None, p, source) for p in ports]
    for a in addrs:
        host, port = split_host_port(a)
        for p in [port] if port else ports:
            out.append(_mk("tcp", host, p, config))
    return out, evidence


# --------------------------------------------------------------------------- nginx
def _nginx_tokens(text: str) -> list[str]:
    toks: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif c in ";{}":
            toks.append(c)
            i += 1
        elif c in "\"'":
            end = text.find(c, i + 1)
            end = n if end < 0 else end
            toks.append(text[i + 1 : end])
            i = end + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in ";{}#\"'":
                j += 1
            toks.append(text[i:j])
            i = j
    return toks


def nginx_listens(fs: RootFS, argv: list[str]) -> tuple[list[ListenAddress], list[str]]:
    """Listeners declared in nginx configuration."""
    configs = _arg(argv[1:], "-c")
    if configs:
        config = configs[-1]
    else:
        config = next(
            (
                c
                for c in (
                    "/etc/nginx/nginx.conf",
                    "/usr/local/nginx/conf/nginx.conf",
                    "/usr/local/openresty/nginx/conf/nginx.conf",
                    "/usr/local/etc/nginx/nginx.conf",
                )
                if fs.is_file(c)
            ),
            "/etc/nginx/nginx.conf",
        )
    prefix = posixpath.dirname(config)
    evidence: list[str] = []
    files = 0

    def load(path: str, depth: int) -> list[str]:
        nonlocal files
        files += 1
        if depth > MAX_DEPTH or files > MAX_FILES:
            return []
        text = fs.try_read_text(path, CONFIG_LIMIT)
        if text is None:
            return []
        evidence.append(path)
        toks = _nginx_tokens(text)
        out: list[str] = []
        i = 0
        while i < len(toks):
            if toks[i] == "include" and i + 1 < len(toks):
                pat = toks[i + 1]
                for inc in fs_glob(fs, pat, cwd=prefix):
                    out.extend(load(inc, depth + 1))
                i += 3 if i + 2 < len(toks) and toks[i + 2] == ";" else 2
                continue
            out.append(toks[i])
            i += 1
        return out

    toks = load(config, 0)
    out: list[ListenAddress] = []
    stack: list[tuple[str, bool]] = []  # (block name, has listen)
    stmt: list[str] = []
    for tok in toks:
        if tok == "{":
            stack.append((stmt[0] if stmt else "", False))
            stmt = []
        elif tok == "}":
            if stack:
                name, had = stack.pop()
                ctx = [b for b, _ in stack]
                if name == "server" and not had and "http" in ctx:
                    out.append(_mk("tcp", None, 80, f"{config} (server without listen: *:80)"))
            stmt = []
        elif tok == ";":
            if stmt and stmt[0] == "listen" and len(stmt) > 1 and stack:
                name, _ = stack[-1]
                stack[-1] = (name, True)
                out.extend(_nginx_listen(stmt[1:], config))
            stmt = []
        else:
            stmt.append(tok)
    return out, evidence


def _nginx_listen(args: list[str], source: str) -> list[ListenAddress]:
    target, params = args[0], args[1:]
    proto = "udp" if ("udp" in params or "quic" in params) else "tcp"
    if target.startswith("unix:"):
        return [ListenAddress(protocol="unix", path=target[5:], scope="local", source=source)]
    host, port = split_host_port(target)
    if port is None and host is not None and not re.match(r"^[\w.\-:]+$", host):
        return []
    return [_mk(proto, host, port if port is not None else 80, source)]


# --------------------------------------------------------------------------- apache
def apache_listens(fs: RootFS, argv: list[str]) -> tuple[list[ListenAddress], list[str]]:
    """``Listen`` directives of Apache httpd."""
    configs = _arg(argv[1:], "-f")
    candidates = configs or [
        "/etc/apache2/apache2.conf",
        "/etc/httpd/conf/httpd.conf",
        "/usr/local/apache2/conf/httpd.conf",
        "/etc/apache2/httpd.conf",
    ]
    config = next((c for c in candidates if fs.is_file(c)), candidates[0])
    root_dir = posixpath.dirname(config)
    server_root = (
        posixpath.dirname(root_dir) if posixpath.basename(root_dir) == "conf" else root_dir
    )
    evidence: list[str] = []
    out: list[ListenAddress] = []
    files = 0

    def parse(path: str, depth: int) -> None:
        nonlocal files, server_root
        files += 1
        if depth > MAX_DEPTH or files > MAX_FILES:
            return
        text = fs.try_read_text(path, CONFIG_LIMIT)
        if text is None:
            return
        evidence.append(path)
        for line in text.replace("\\\n", " ").splitlines():
            parts = line.strip().split()
            if not parts or parts[0].startswith("#"):
                continue
            key = parts[0].lower()
            if key == "serverroot" and len(parts) > 1:
                server_root = parts[1].strip("\"'")
            elif key in ("include", "includeoptional") and len(parts) > 1:
                pat = parts[1].strip("\"'")
                for inc in fs_glob(fs, pat, cwd=server_root):
                    if fs.is_dir(inc):
                        for name in fs.safe_listdir(inc):
                            parse(posixpath.join(inc, name), depth + 1)
                    else:
                        parse(inc, depth + 1)
            elif key == "listen" and len(parts) > 1:
                host, port = split_host_port(parts[1])
                if port is None and host is not None and host.isdigit():
                    port = int(host)
                    host = None
                if port is not None:
                    out.append(_mk("tcp", host, port, path))

    parse(config, 0)
    return out, evidence


DAEMONS: dict[str, Listener] = {
    "sshd": sshd_listens,
    "nginx": nginx_listens,
    "openresty": nginx_listens,
    "apache2": apache_listens,
    "httpd": apache_listens,
    "apachectl": apache_listens,
    "apache2ctl": apache_listens,
}


def daemon_listens(
    fs: RootFS, executable: str | None, argv: list[str] | None = None
) -> tuple[list[ListenAddress], list[str]]:
    """Listeners declared by the configuration of a well-known daemon (else empty)."""
    if not executable:
        return [], []
    fn = DAEMONS.get(posixpath.basename(executable))
    if fn is None:
        return [], []
    listens, evidence = fn(fs, list(argv or [executable]))
    return dedupe(listens), evidence


def dedupe(listens: list[ListenAddress]) -> list[ListenAddress]:
    """Remove duplicate listeners and sort deterministically."""
    seen: dict[tuple[str, str, int, str, str], ListenAddress] = {}
    for la in listens:
        key = (la.protocol, la.address or "", la.port or -1, la.path or "", la.scope)
        seen.setdefault(key, la)
    return [seen[k] for k in sorted(seen)]


def exposed_port_listens(ports: list[str], source: str) -> list[ListenAddress]:
    """OCI ``ExposedPorts`` entries (``80/tcp``, ``53/udp``, ``8080``) → network listeners."""
    out: list[ListenAddress] = []
    for raw in ports:
        port_s, _, proto = raw.strip().partition("/")
        proto = (proto or "tcp").lower()
        if "-" in port_s:
            lo, _, hi = port_s.partition("-")
            if lo.isdigit() and hi.isdigit() and int(hi) - int(lo) < 1024:
                out.extend(
                    ListenAddress(protocol=proto, port=p, scope="network", source=source)
                    for p in range(int(lo), int(hi) + 1)
                )
            continue
        if port_s.isdigit() and int(port_s) <= 65535:
            out.append(
                ListenAddress(protocol=proto, port=int(port_s), scope="network", source=source)
            )
    return dedupe(out)


# --------------------------------------------------------------------------- service helpers
def base_hardening(
    *,
    user: str | None = "root",
    group: str | None = None,
    no_new_privileges: bool = False,
    ambient: list[str] | None = None,
    root_directory: str | None = None,
) -> Hardening:
    """Hardening of a service whose manager offers no sandbox (systemd-equivalent exposure)."""
    s = SecurityInput(
        user=user or None,
        no_new_privileges=no_new_privileges,
        ambient_capabilities=frozenset(ambient or ()),
        root_directory=root_directory,
    )
    return to_hardening(s, group=group)


def command_from(directive: str, argv: list[str], raw: str, res: Resolution) -> Command:
    """Build a :class:`Command` from an unwrap :class:`Resolution`."""
    return Command(
        directive=directive,
        argv=argv,
        raw=raw,
        executable=res.executable,
        wrapped_by=res.wrappers,
    )


def finish_service(
    fs: RootFS, svc: Service, extra_executables: list[str] | None = None, *, netconf: bool = True
) -> Service:
    """Fill ``executables`` (sorted, deduped) and config-declared listeners; dedupe evidence."""
    exes: set[str] = set(extra_executables or [])
    for cmd in svc.commands:
        if cmd.executable:
            exes.add(cmd.executable)
        exes.update(cmd.wrapped_by)
    svc.executables = sorted(exes)
    found = list(svc.listens)
    if netconf and not any(la.protocol in ("tcp", "udp", "sctp") for la in found):
        for cmd in svc.commands:
            listens, evidence = daemon_listens(fs, cmd.executable, daemon_argv(cmd))
            found.extend(listens)
            svc.evidence.extend(evidence)
    svc.listens = dedupe(found)
    svc.evidence = list(dict.fromkeys(svc.evidence))
    return svc


def daemon_argv(cmd: Command) -> list[str]:
    """Best guess at the daemon's own argv (leading wrapper words stripped)."""
    if not cmd.executable:
        return cmd.argv
    base = posixpath.basename(cmd.executable)
    for i, a in enumerate(cmd.argv):
        if posixpath.basename(a) == base:
            return cmd.argv[i:]
    return [cmd.executable]
