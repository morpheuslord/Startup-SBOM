# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (PEP 440 spelling for
pre-releases, e.g. `2.1.0rc1`).

The release workflow copies the section whose heading matches the pushed tag
(`## [X.Y.Z]`) into the GitHub release notes.

## [Unreleased]

## [2.0.0] - 2026-10-12

A ground-up rewrite. Startup-SBOM is now a root-confined static analyser that
never executes, mounts or writes into the system it inspects. See
`Docs/Refactor Plan.md` for the complete audit-finding-to-fix ledger.

### Added

- New `startup-sbom` CLI (Typer): `scan`, `db update|status|clear`, `schema`, `version`,
  `tui`, `intel` and `ai`.
- Explicit target schemes: `dir:`, `host:`, `tar:`, `docker-archive:`, `oci-dir:`,
  `oci-archive:`, `docker:`, `podman:`, `nerdctl:` (an existing bare path is auto-detected).
- Output formats: native JSON (with a published JSON Schema), CycloneDX 1.5/1.6/1.7,
  SPDX 2.3, SARIF 2.1.0, OpenVEX, CycloneDX VEX, Markdown, self-contained HTML,
  Graphviz DOT and Mermaid attack graphs, written atomically into one output directory;
  PDF reports via Typst (`-f pdf`, `pdf` extra), PDF/A-3u + PDF/UA-1 by default with the
  JSON report attached.
- Package databases: dpkg (including distroless `status.d`), RPM (sqlite, Berkeley DB,
  NDB; pure Python), apk, alpm; exact, usr-merge-aware file ownership index.
- Init systems: systemd (search paths, drop-ins, masks, templates, sockets, boot graph,
  hardening exposure), SysV/LSB, OpenRC, runit, s6, supervisord, busybox inittab and
  container entrypoints.
- ELF loader emulation inside the root (DT_NEEDED, RUNPATH, `ld.so.cache`,
  `.note.dlopen`, `ld.so.preload`) linking services to the libraries they load.
- Vulnerabilities from OSV.dev matched by source package, full epoch version and exact
  distro ecosystem; Arch security tracker; optional NVD; EPSS and CISA KEV enrichment;
  end-of-life data; offline mode backed by a local cache (`startup-sbom db`).
- Threat reversal (pre/post-conditions, reachability, ATT&CK, SSVC, risk score),
  chained attack-path graph and supply-chain blast-radius analysis.
- Explainable results: exact additive risk explanations (baseline + contributions =
  total), SSVC decision traces with counterfactual flips, minimal fix plans that break
  every attack chain, and system-wide risk drivers, rendered as terminal charts and
  SVG in the console, HTML, Markdown and PDF outputs.
- Interactive terminal UI (`startup-sbom tui`, `tui` extra): target picker, scan
  settings, live scan progress with cancellation, and a results browser.
- Opt-in online intel prefetch (`--prefetch-intel`): vendor advisories, exploit and PoC
  references and articles for the highest-risk findings, through an SSRF-hardened
  fetcher; public exploitation evidence can only raise a threat's priority.
- AI analysis (`startup-sbom ai`, `ai` extra) on Anthropic, OpenAI, Google, Groq,
  Mistral, OpenRouter or Ollama, with cost ceilings, optional DuckDuckGo search and
  grounding checks that flag claims the report does not support; served over MCP and
  as A2A / ACP agent endpoints (`agents-server` extra).
- `--fail-on` gate with documented exit codes (0 ok, 1 threshold reached,
  2 usage/target error, 3 internal error).
- Distribution: PyPI package (`uvx startup-sbom`), multi-arch non-root container image
  `ghcr.io/morpheuslord/startup-sbom`, composite GitHub Action with SARIF upload, and
  pre-commit hooks (`startup-sbom`, `startup-sbom-offline`).
- Supply-chain hardening of the project itself: `uv.lock`, SHA-pinned actions, zizmor,
  CodeQL, Codacy, Dependabot (uv, actions, docker, pre-commit, npm), PyPI Trusted Publishing with
  PEP 740 attestations, GitHub build-provenance attestations, image SBOM/provenance,
  and a CycloneDX SBOM of the tool's own dependencies attached to each release.
- Documentation site (MkDocs Material) at https://morpheuslord.github.io/Startup-SBOM/.

### Changed

- Packaging migrated to `uv` with the `uv_build` backend and a `src/` layout;
  Python 3.11+ is required (3.10 is end-of-life).
- CycloneDX output rebuilt on `cyclonedx-python-lib`: spec-compliant purls with distro,
  arch and epoch qualifiers, unique bom-refs, OS component, dependency graph,
  services and vulnerabilities.
- Output ordering is canonical, so repeated scans produce identical reports.
- Reports are written owner-only (0600), since they describe a system's weaknesses.
- `dir:` targets on a Windows host warn that NTFS cannot store POSIX permission bits, so
  executable, setuid and capability findings are incomplete; scan an archive instead.

### Removed

- "chroot" mode, all use of `sudo`, `chroot`, bind mounts and `systemd-analyze` inside the
  target. Boot timing is now read from a user-supplied file (`--boot-timing`).
- Extraction of container exports to disk; archives are read in place through a
  read-only virtual filesystem.
- NVD keyword search and the `rpm` shim that read the host's RPM database.
- `requirements.txt`; dependencies are declared in `pyproject.toml` and locked in `uv.lock`.

### Security

- Fixed arbitrary directory deletion via an unvalidated `--docker` reference (C-1).
- Fixed host filesystem modification by the old chroot mode (C-2) and execution of
  untrusted target binaries as root (C-3).
- Target symlinks can no longer resolve to host files; FIFOs, devices and oversized files
  are refused (C-4).
- Vulnerability lookup failures are reported as coverage gaps instead of a silent
  "0 CVEs" (C-5).
- Untrusted archives are no longer extracted (H-1); container environment values are
  never written to disk (H-2); untrusted strings are escaped in every output (H-12, M-1).

## [release-1] - 2026-03-29

Initial public release (`main.py` + `sbom_manager/`): dpkg/rpm startup-service mapping,
NVD lookups, CycloneDX output and service flowcharts. Archived at DOI
[10.5281/zenodo.19307312](https://doi.org/10.5281/zenodo.19307312).

[Unreleased]: https://github.com/morpheuslord/Startup-SBOM/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/morpheuslord/Startup-SBOM/compare/release-1...v2.0.0
[release-1]: https://github.com/morpheuslord/Startup-SBOM/tree/release-1
