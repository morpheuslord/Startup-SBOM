"""Pure TUI state (no Textual import): form → request, CLI preview, recent scans, IO helpers."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from startup_sbom.context import ScanOptions
from startup_sbom.errors import StartupSBOMError, TargetError
from startup_sbom.models import SCHEMA_VERSION, Report
from startup_sbom.textsafe import safe

SCHEMES: tuple[str, ...] = (
    "dir",
    "host",
    "tar",
    "docker-archive",
    "oci-dir",
    "oci-archive",
    "docker",
    "podman",
    "nerdctl",
)
PATH_SCHEMES = frozenset({"dir", "tar", "docker-archive", "oci-dir", "oci-archive"})
DIR_SCHEMES = frozenset({"dir", "oci-dir"})
ENGINE_SCHEMES: tuple[str, ...] = ("docker", "podman", "nerdctl")
VULN_SOURCES: tuple[str, ...] = ("osv", "arch", "nvd")
DEFAULT_SOURCES: tuple[str, ...] = ("osv", "arch")  # the CLI default
FAIL_ON: tuple[str, ...] = ("none", "low", "medium", "high", "critical", "attend", "act")
CDX_SPECS: tuple[str, ...] = ("1.5", "1.6", "1.7")
AI_PROFILES: tuple[str, ...] = ("cheap", "balanced", "quality")
AI_AUDIENCES: tuple[str, ...] = ("technical", "executive")
DEFAULT_OUTPUT = "startup-sbom-out"
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_RECENT = 20
_RECENT_FILE_CAP = 1024 * 1024


class TuiError(StartupSBOMError):
    """A user-facing TUI problem (bad report file, failed engine listing, ...)."""


def available_formats() -> list[str]:
    """Every output format the report package offers (``pdf`` when registered)."""
    from startup_sbom.report import FORMATS

    return list(FORMATS)


def default_filename(fmt: str) -> str:
    """Default output file name of ``fmt``."""
    from startup_sbom.report import FORMATS

    spec = FORMATS.get(fmt)
    return spec.default_filename if spec is not None else f"report.{fmt}"


# --------------------------------------------------------------------------- form model
@dataclass(slots=True)
class AISettings:
    """AI analyst options (provider keys come from the environment only).

    ``enabled`` runs the post-scan assessment; ``live`` lets the live analyst
    comment on each stage while the scan runs (display-only).  Both share the
    provider, model, profile and per-run spending cap.
    """

    enabled: bool = False
    live: bool = False
    provider: str | None = None
    model: str | None = None
    profile: str = "cheap"
    audience: str = "technical"
    max_cost_usd: float = 1.0


@dataclass(slots=True)
class FormValues:
    """Every scan setting the TUI exposes; mirrors ``startup-sbom scan`` options."""

    target: str = ""
    offline: bool = False
    sources: tuple[str, ...] = DEFAULT_SOURCES
    epss: bool = True
    kev: bool = True
    eol: bool = True
    language_packages: bool = True
    link_analysis: bool = True
    integrity: bool = False
    platform: str = ""
    boot_timing: str = ""
    cdx_spec: str = "1.6"
    vex_unreachable: bool = False
    formats: tuple[str, ...] = ("json",)
    output_dir: str = DEFAULT_OUTPUT
    fail_on: str = "none"
    prefetch_intel: bool = False
    intel_max_cves: int = 25
    intel_max_articles: int = 4
    intel_budget: float = 120.0
    intel_articles: bool = True
    ai_enabled: bool = False
    ai_live: bool = False
    ai_provider: str = ""
    ai_model: str = ""
    ai_profile: str = "cheap"
    ai_audience: str = "technical"
    ai_max_cost: float = 1.0


@dataclass(slots=True)
class ScanRequest:
    """Everything the live scan screen needs."""

    target: str
    options: ScanOptions
    formats: tuple[str, ...] = ()
    output_dir: Path = field(default_factory=lambda: Path(DEFAULT_OUTPUT))
    fail_on: str = "none"
    cdx_spec: str = "1.6"
    vex_unreachable: bool = False
    ai: AISettings = field(default_factory=AISettings)


def compose_target(scheme: str, reference: str) -> str:
    """``scheme`` + reference → target string (``host:`` takes none; ``auto`` = bare path)."""
    if scheme == "host":
        return "host:"
    if scheme == "auto":
        return reference.strip()
    return f"{scheme}:{reference.strip()}"


def split_target(target: str) -> tuple[str, str]:
    """Inverse of :func:`compose_target` for prefilling the picker."""
    text = target.strip()
    if not text:
        return "dir", ""
    scheme, sep, rest = text.partition(":")
    if sep and scheme.lower() in SCHEMES:
        return scheme.lower(), "" if scheme.lower() == "host" else rest
    return "auto", text


def check_target(target: str) -> str:
    """Validate ``target`` with the same parser the CLI uses; returns it normalised.

    Raises :class:`~startup_sbom.errors.TargetError` with a user-facing message.
    """
    from startup_sbom.sources import parse_target

    spec = parse_target(target)
    return "host:" if spec.scheme == "host" else target.strip()


def validate_values(values: FormValues) -> list[str]:
    """Problems that block starting a scan (empty list = OK)."""
    errors: list[str] = []
    try:
        check_target(values.target)
    except TargetError as exc:
        errors.append(f"target: {safe(exc)}")
    unknown = set(values.sources) - set(VULN_SOURCES)
    if unknown:
        errors.append(f"unknown vulnerability source(s): {', '.join(sorted(unknown))}")
    if values.platform.strip():
        from startup_sbom.sources import Platform

        try:
            Platform.parse(values.platform)
        except TargetError as exc:
            errors.append(f"platform: {safe(exc)}")
    if values.boot_timing.strip():
        path = Path(values.boot_timing.strip()).expanduser()
        if not path.is_file():
            errors.append(f"boot-timing file not found: {safe(values.boot_timing)}")
    if values.formats and not values.output_dir.strip():
        errors.append("an output directory is required when formats are selected")
    if values.fail_on not in FAIL_ON:
        errors.append(f"fail-on must be one of {', '.join(FAIL_ON)}")
    if values.cdx_spec not in CDX_SPECS:
        errors.append(f"CycloneDX spec must be one of {', '.join(CDX_SPECS)}")
    if values.intel_max_cves < 1:
        errors.append("intel: max CVEs must be at least 1")
    if values.intel_max_articles < 0:
        errors.append("intel: max articles cannot be negative")
    if values.intel_budget <= 0:
        errors.append("intel: time budget must be positive")
    if values.ai_profile not in AI_PROFILES:
        errors.append(f"AI profile must be one of {', '.join(AI_PROFILES)}")
    if values.ai_audience not in AI_AUDIENCES:
        errors.append(f"AI audience must be one of {', '.join(AI_AUDIENCES)}")
    if values.ai_max_cost < 0:
        errors.append("AI max cost cannot be negative")
    return errors


def build_request(values: FormValues, env: Mapping[str, str] | None = None) -> ScanRequest:
    """Map form values to a :class:`ScanRequest` exactly like ``cli.scan`` maps its flags."""
    environ = os.environ if env is None else env
    cache = environ.get("STARTUP_SBOM_CACHE_DIR")
    boot = values.boot_timing.strip()
    options = ScanOptions(
        offline=values.offline,
        vuln_sources=tuple(s for s in VULN_SOURCES if s in values.sources),
        nvd_api_key=environ.get("NVD_API_KEY") or None,
        epss=values.epss,
        kev=values.kev,
        eol=values.eol,
        cache_dir=Path(cache) if cache else None,
        language_packages=values.language_packages,
        link_analysis=values.link_analysis,
        integrity_check=values.integrity,
        platform=values.platform.strip() or None,
        boot_timing_file=Path(boot).expanduser() if boot else None,
        vex_not_affected_unreachable=values.vex_unreachable,
        prefetch_intel=values.prefetch_intel and not values.offline,
        intel_max_cves=values.intel_max_cves,
        intel_max_articles=values.intel_max_articles,
        intel_budget=values.intel_budget,
        intel_articles=values.intel_articles,
    )
    ai = AISettings(
        enabled=values.ai_enabled and not values.offline,
        live=values.ai_live and not values.offline,
        provider=values.ai_provider or None,
        model=values.ai_model.strip() or None,
        profile=values.ai_profile,
        audience=values.ai_audience,
        max_cost_usd=values.ai_max_cost,
    )
    return ScanRequest(
        target=values.target.strip(),
        options=options,
        formats=tuple(dict.fromkeys(values.formats)),
        output_dir=Path(values.output_dir.strip() or DEFAULT_OUTPUT).expanduser(),
        fail_on=values.fail_on,
        cdx_spec=values.cdx_spec,
        vex_unreachable=values.vex_unreachable,
        ai=ai,
    )


def equivalent_cli(values: FormValues) -> str:
    """The ``startup-sbom scan`` command line equivalent to ``values`` (shell-quoted)."""
    defaults = FormValues()
    args = ["startup-sbom", "scan", values.target.strip() or "<target>"]
    for fmt in dict.fromkeys(values.formats):
        args += ["-f", fmt]
    if values.formats:
        args += ["-o", values.output_dir.strip() or DEFAULT_OUTPUT]
    if values.offline:
        args.append("--offline")
    sources = tuple(s for s in VULN_SOURCES if s in values.sources)
    if sources != DEFAULT_SOURCES:
        args += ["--sources", ",".join(sources) or "none"]
    flags = (
        (not values.epss, "--no-epss"),
        (not values.kev, "--no-kev"),
        (not values.eol, "--no-eol"),
        (not values.language_packages, "--no-language-packages"),
        (not values.link_analysis, "--no-link-analysis"),
        (values.integrity, "--integrity"),
    )
    args += [flag for on, flag in flags if on]
    if values.platform.strip():
        args += ["--platform", values.platform.strip()]
    if values.boot_timing.strip():
        args += ["--boot-timing", values.boot_timing.strip()]
    if values.cdx_spec != defaults.cdx_spec:
        args += ["--cdx-spec", values.cdx_spec]
    if values.vex_unreachable:
        args.append("--vex-unreachable-not-affected")
    if values.fail_on != "none":
        args += ["--fail-on", values.fail_on]
    if values.prefetch_intel and not values.offline:
        args.append("--intel")
        if values.intel_max_cves != defaults.intel_max_cves:
            args += ["--intel-max-cves", str(values.intel_max_cves)]
        if values.intel_max_articles != defaults.intel_max_articles:
            args += ["--intel-max-articles", str(values.intel_max_articles)]
        if values.intel_budget != defaults.intel_budget:
            args += ["--intel-budget", f"{values.intel_budget:g}"]
        if not values.intel_articles:
            args.append("--no-intel-articles")
    if values.ai_enabled and not values.offline:
        args.append("--ai")
        if values.ai_provider:
            args += ["--ai-provider", values.ai_provider]
        if values.ai_model.strip():
            args += ["--ai-model", values.ai_model.strip()]
        if values.ai_profile != defaults.ai_profile:
            args += ["--ai-profile", values.ai_profile]
        if values.ai_audience != defaults.ai_audience:
            args += ["--ai-audience", values.ai_audience]
        if values.ai_max_cost != defaults.ai_max_cost:
            args += ["--ai-max-cost", f"{values.ai_max_cost:g}"]
    if values.ai_live and not values.offline:
        args.append("--ai-live")
        if values.ai_provider and not values.ai_enabled:
            args += ["--ai-provider", values.ai_provider]
        if values.ai_model.strip() and not values.ai_enabled:
            args += ["--ai-model", values.ai_model.strip()]
        args += ["--ai-budget", f"{values.ai_max_cost:g}"]
    return shlex.join(args)


# --------------------------------------------------------------------------- reports
def load_report(path: Path, max_bytes: int = MAX_REPORT_BYTES) -> Report:
    """Read and validate a native ``report.json`` (regular file, size-capped)."""
    path = Path(path).expanduser()
    try:
        st = path.stat()
    except OSError as exc:
        raise TuiError(f"cannot open {path}: {exc.strerror or exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise TuiError(f"not a regular file: {path}")
    if st.st_size > max_bytes:
        raise TuiError(f"{path} is larger than {max_bytes // (1024 * 1024)} MiB")
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError as exc:
        raise TuiError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(raw) > max_bytes:
        raise TuiError(f"{path} is larger than {max_bytes // (1024 * 1024)} MiB")
    try:
        head = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise TuiError(f"{path} is not valid JSON: {exc}") from exc
    version = (head.get("metadata") or {}).get("schema_version") if isinstance(head, dict) else None
    if isinstance(version, str) and version.split(".")[0] != SCHEMA_VERSION.split(".")[0]:
        raise TuiError(
            f"{path} uses report schema {version}; this version reads {SCHEMA_VERSION}.x"
        )
    try:
        return Report.model_validate(head)
    except ValueError as exc:
        first = str(exc).splitlines()[:3]
        raise TuiError(f"{path} is not a startup-sbom report: {' '.join(first)}") from exc


# --------------------------------------------------------------------------- recent scans
@dataclass(slots=True)
class RecentEntry:
    """A recently opened or written ``report.json`` (paths and counts only; no secrets)."""

    path: str
    target: str = ""
    when: str = ""
    threats: int = 0
    act: int = 0


def default_data_dir() -> Path:
    """Per-user data directory of the TUI."""
    import platformdirs

    return platformdirs.user_data_path("startup-sbom", appauthor=False)


def entry_for(report: Report, path: Path) -> RecentEntry:
    """A :class:`RecentEntry` describing ``report`` stored at ``path``."""
    return RecentEntry(
        path=str(Path(path).expanduser().resolve()),
        target=safe(report.metadata.target.reference, 200),
        when=datetime.now(UTC).strftime("%Y-%m-%d %H:%M"),
        threats=report.summary.threats,
        act=report.summary.act,
    )


class RecentStore:
    """A tiny JSON list of recent report paths in the user data directory."""

    def __init__(self, directory: Path, limit: int = MAX_RECENT) -> None:
        self.path = Path(directory) / "recent.json"
        self.limit = limit

    def load(self) -> list[RecentEntry]:
        """Entries, newest first; a missing or corrupt file yields an empty list."""
        try:
            if not self.path.is_file() or self.path.stat().st_size > _RECENT_FILE_CAP:
                return []
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            return []
        if not isinstance(data, list):
            return []
        out: list[RecentEntry] = []
        for item in data[: self.limit]:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                continue
            out.append(
                RecentEntry(
                    path=item["path"],
                    target=str(item.get("target", "")),
                    when=str(item.get("when", "")),
                    threats=_int(item.get("threats")),
                    act=_int(item.get("act")),
                )
            )
        return out

    def add(self, entry: RecentEntry) -> list[RecentEntry]:
        """Insert ``entry`` at the top (deduplicated by path) and persist."""
        entries = [e for e in self.load() if e.path != entry.path]
        entries.insert(0, entry)
        return self.save(entries[: self.limit])

    def remove(self, path: str) -> list[RecentEntry]:
        """Forget ``path``."""
        return self.save([e for e in self.load() if e.path != path])

    def save(self, entries: list[RecentEntry]) -> list[RecentEntry]:
        """Atomically write ``entries`` (errors are swallowed: history is best-effort)."""
        payload = json.dumps([asdict(e) for e in entries], indent=1)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".recent.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                os.replace(tmp, self.path)
            except OSError:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError:
            pass
        return entries


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


# --------------------------------------------------------------------------- containers
@dataclass(frozen=True, slots=True)
class ContainerRow:
    """One row of ``<engine> ps -a`` (untrusted engine output)."""

    engine: str
    id: str
    name: str
    image: str
    state: str


def parse_ps_output(engine: str, text: str) -> list[ContainerRow]:
    """Parse ``--format '{{json .}}'`` output: JSON Lines (docker/nerdctl) or an array."""
    text = text.strip()
    if not text:
        return []
    items: list[object] = []
    try:
        if text.startswith("["):
            loaded = json.loads(text)
            items = loaded if isinstance(loaded, list) else []
        else:
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (ValueError, RecursionError) as exc:
        raise TuiError(f"{engine} ps: unexpected output ({exc})") from exc
    rows: list[ContainerRow] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        names = item.get("Names") or item.get("Name") or ""
        if isinstance(names, list):
            names = ",".join(str(n) for n in names)
        rows.append(
            ContainerRow(
                engine=engine,
                id=str(item.get("ID") or item.get("Id") or "")[:12],
                name=str(names).lstrip("/"),
                image=str(item.get("Image", "")),
                state=str(item.get("State", "") or item.get("Status", "")),
            )
        )
    return rows


Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def list_containers(
    engine: str, *, timeout: float = 5.0, runner: Runner | None = None
) -> list[ContainerRow]:
    """``<engine> ps -a --format '{{json .}}'``: absolute path, argv list, timeout, exit checked."""
    if engine not in ENGINE_SCHEMES:
        raise TuiError(f"unsupported engine {engine!r}")
    exe = shutil.which(engine)
    if exe is None:
        raise TuiError(f"{engine} is not installed (type a container or image name instead)")
    run = runner or subprocess.run
    try:
        proc = run(
            [exe, "ps", "-a", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TuiError(f"{engine} ps timed out after {timeout:g}s") from exc
    except OSError as exc:
        raise TuiError(f"cannot run {engine}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()[:300] or f"exit status {proc.returncode}"
        raise TuiError(f"{engine} ps failed: {detail}")
    return parse_ps_output(engine, proc.stdout or "")
