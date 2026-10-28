# Integration

Startup-SBOM is designed to slot into pipelines: a plain Python package with stable exit codes, a container image, a composite GitHub Action, pre-commit hooks, a library API and a published JSON Schema. This page collects the supported integration paths; the output formats they produce are described in [Outputs](outputs.md).

## Installing

Python ≥ 3.11 on Linux, macOS or Windows. Everything except `host:` mode and live container acquisition is pure Python and host-OS independent.

```bash
uv tool install startup-sbom        # or: pipx install startup-sbom
uvx startup-sbom --help             # run once without installing
```

Optional extras:

| Extra | Adds |
|---|---|
| `startup-sbom[tui]` | the interactive terminal UI (`startup-sbom tui`) |
| `startup-sbom[pdf]` | the PDF renderer (Typst) |
| `startup-sbom[ai]` | AI analysis, MCP server, web search (pydantic-ai, mcp) |
| `startup-sbom[agents-server]` | A2A/ACP agent serving (fasta2a, uvicorn); implies `ai` |
| `startup-sbom[all]` | everything above |

From source:

```bash
git clone https://github.com/morpheuslord/Startup-SBOM && cd Startup-SBOM
uv sync
uv run startup-sbom --help
```

The build backend is `uv_build`; `uv sync` installs the dev dependency groups (pytest, ruff, mypy) as well. The 1.x entry point `python3 main.py …` still works through a compatibility shim that maps the old flags onto a 2.x scan.

## Docker

```bash
# Scan a mounted rootfs, fully offline
docker run --rm --network none \
  -v /path/to/rootfs:/target:ro -v "$PWD/out:/out" --user "$(id -u):$(id -g)" \
  ghcr.io/morpheuslord/startup-sbom scan dir:/target --offline -f cyclonedx -o /out

# Scan an exported image archive
docker run --rm -v "$PWD:/in:ro" -v "$PWD/out:/out" --user "$(id -u):$(id -g)" \
  ghcr.io/morpheuslord/startup-sbom scan docker-archive:/in/image.tar -o /out
```

The image runs as an unprivileged user (uid 65532). If the mounted rootfs contains root-only files (`/var/lib/rpm`, `/etc/sudoers.d`, …), add `--user 0` — the scanner still never executes, mounts or writes anything inside the target, and the target should stay mounted read-only. The image does not include bubblewrap, so [chroot mode](chroot-mode.md) is not available in it: `--mode chroot` warns and falls back to static analysis. The Docker socket is **not** needed for `dir:`/`tar:`/`docker-archive:`/`oci-*` targets; do not mount it unless you deliberately want `docker:NAME` acquisition. Persist the vulnerability cache across runs with `-v startup-sbom-cache:/cache`.

## GitHub Action

The repository root ships a composite action (`action.yml`):

```yaml
permissions:
  contents: read
  security-events: write   # only needed when upload-sarif is true
steps:
  - uses: morpheuslord/Startup-SBOM@v2
    with:
      target: oci-archive:image.tar
      formats: sarif,cyclonedx,json
      fail-on: act
```

Inputs: `target` (required), `formats` (default `sarif,cyclonedx,json`), `output-dir`, `offline`, `fail-on`, `extra-args` (whitespace-split flags such as `--no-epss --cdx-spec 1.7`), `version` (install a released version from PyPI; empty runs the code at the pinned ref), `python-version`, `upload-sarif` (default `true`), `sarif-category` and `nvd-api-key`. Outputs: `sarif-file`, `sbom-file`, `report-file`, `output-dir` and `exit-code`.

The action installs uv, runs the scanner via `uvx`, writes a job-summary table, and uploads `results.sarif` to **GitHub code scanning** using `github/codeql-action/upload-sarif` (the CodeQL action is only the upload vehicle — no CodeQL analysis runs). Findings then appear as code-scanning alerts under the chosen category. Reports and the SARIF upload are produced *before* the `fail-on` exit code is applied, so artefacts survive a failing gate. Every input reaches the scanner through environment variables as discrete argv entries; nothing is interpolated into shell source.

## pre-commit

`.pre-commit-hooks.yaml` offers two hooks. Startup-SBOM scans a whole rootfs or image archive, not individual changed files, so filenames are never passed — give the target in `args`:

```yaml
repos:
  - repo: https://github.com/morpheuslord/Startup-SBOM
    rev: v2.0.4
    hooks:
      - id: startup-sbom            # or: startup-sbom-offline (adds --offline --quiet)
        args: [dir:rootfs, -f, cyclonedx, -o, sbom-out, --fail-on, high]
        files: ^rootfs/
```

Both hooks run on `pre-commit`, `pre-push` and `manual` stages and require Python ≥ 3.11 in the hook environment.

## Library usage

The public API is one function and one options dataclass, re-exported at the top level:

```python
from startup_sbom import Report, ScanOptions, scan

options = ScanOptions(
    offline=True,  # cached intelligence only, no sockets
    vuln_sources=("osv", "arch"),  # add "nvd" with nvd_api_key for CPE fallback
    language_packages=True,
    integrity_check=False,
    mode="static",  # "chroot" / "auto": sandboxed confirmation probes (dir:/host: targets)
)
report: Report = scan("docker-archive:image.tar", options)

for threat in report.threats:
    if threat.ssvc and threat.ssvc.decision in ("Act", "Attend"):
        print(threat.risk_score, threat.title, threat.narrative)

for chain in report.attack_chains:
    print(chain.score, chain.ssvc_decision, chain.narrative)
```

`scan()` accepts the same target schemes as the CLI, plus a `progress` callback, an `activity` callback that receives raw operations and stage digests as they happen ([Live Scanning](live-scanning.md)), `strict=True` to make stage failures raise instead of degrade, and a `threading.Event` for cooperative cancellation. Other `ScanOptions` fields mirror CLI flags, among them `derivative_fallback` (`--no-derivative-fallback`) and `cvss_impact_gate` (`--no-cvss-impact-gate`). Rendering is a separate step:

```python
from pathlib import Path
from startup_sbom.report import RenderOptions, render, render_bytes, write_reports

markdown = render(report, "markdown")
pdf = render_bytes(report, "pdf")  # needs startup-sbom[pdf]
write_reports(report, {"cyclonedx": Path("out/sbom.cdx.json")}, RenderOptions(cdx_spec="1.7"))
```

The exit-code policy is available programmatically as `startup_sbom.cli.policy_violated(report, fail_on)`.

## The JSON schema

```bash
startup-sbom schema > report.schema.json
```

prints the JSON Schema of the native report (`Report`, versioned via `metadata.schema_version`, currently `2.2`). The models forbid unknown fields, so any `report.json` produced by the tool validates against the schema of its version — use it to pin consumers, generate typed clients, or validate archived reports. See [Architecture](architecture.md) for the model itself and [Outputs](outputs.md) for the native format.
