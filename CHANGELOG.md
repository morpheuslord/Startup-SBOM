# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (PEP 440 spelling for
pre-releases, e.g. `2.1.0rc1`).

The release workflow copies the section whose heading matches the pushed tag
(`## [X.Y.Z]`) into the GitHub release notes.

## [2.0.4] - 2026-10-28

Security release. The scanner's own code is unchanged; this release ships patched
dependencies.

### Security

- **certifi 2026.10.23** (was 2026.7.22): drops the emSign root CAs whose intermediate
  CA keys were compromised (GHSA-6q48-6c7w-9gw2). certifi supplies the trust store for
  every HTTPS request the scanner makes, including vulnerability-database lookups, so
  this affects every install.
- **fastmcp-slim 4.1.4** (was 4.1.0) and **authlib 1.9.1** (was 1.8.0), used only by the
  `ai` and `agents-server` extras. The fastmcp-slim update fixes skipped authorization
  on direct calls to transformed components (GHSA-7xgj-8392-5q4r) and MCP client OAuth
  providers built without issuer binding, which could send the client secret to an
  attacker's authorization server (GHSA-vqqp-x5qm-5qp4). fastmcp-slim also no longer
  pulls in keyring and its helpers.
- The container image and `uv.lock` carry these versions. If you installed with pip or
  `uv tool`, upgrade the dependencies as well as startup-sbom, for example with
  `uv tool upgrade startup-sbom` or `pip install -U --upgrade-strategy eager startup-sbom`.
- The Codacy Analysis CLI used by the security workflow is patched to undici 6.29.1 and
  fast-uri 3.1.9. This is CI tooling only and is not shipped.

### Changed

- The GitHub Action uploads SARIF with `github/codeql-action/upload-sarif` v4.39.0.
- The container image is built with uv 0.13.5.
- Routine dependency updates: platformdirs 4.13.5, pydantic 2.14.1, filelock 4.2.1,
  virtualenv 21.14.13.

### Fixed

- **Fixed Codacy findings stayed open in code scanning.** The Codacy CLI leaves a tool
  out of its SARIF output once that tool has nothing to report, so code scanning never
  saw a new analysis for it and kept the old alerts open. The security workflow now
  uploads an empty result for each clean tool, which closes alerts that are fixed.

## [2.0.3] - 2026-10-18

GitHub Marketplace release.

### Changed

- **The GitHub Action is on the GitHub Marketplace** as *Startup-SBOM Scan*. Its
  description is shortened to fit the Marketplace's 125-character limit; the action's
  inputs, outputs and behaviour are unchanged.
- The container image is built with uv 0.13.1.

### Fixed

- **`uses: morpheuslord/Startup-SBOM@v2` did not resolve.** The README and docs showed
  `@v2`, but no `v2` tag existed. A `v2` tag now follows the latest 2.x release. For
  supply-chain safety, pinning to a full commit SHA is still recommended.

## [2.0.2] - 2026-10-13

Bug-fix release.

### Fixed

- **Live analyst stopped with an error.** With `--ai-live` (or the TUI's live analyst)
  on Claude Haiku 4.5, the analyst failed at the first stage with
  "`max_tokens` must be greater than `thinking.budget_tokens`". It no longer sets its
  own token limit, so the model can think as usual and the request is accepted.
  Spending is still capped by `--ai-budget`.
- **Release workflow failed when the release already existed.** If a GitHub release for
  the tag was already there (for example one made on the Releases page), the workflow
  stopped with an error. It now leaves that release as it is and finishes.
- **Container image rebuilt on every release run.** Re-running a release no longer
  rebuilds and re-pushes an image that is already published for that version.

## [2.0.1] - 2026-10-13

### Added

- Chroot mode (`startup-sbom scan --mode static|chroot|auto`, `ScanOptions.mode`): a new
  pipeline stage asks the target's own dynamic loader (`ld.so --list`),
  `systemctl --root=/ list-unit-files` and package manager (`dpkg-query`, `rpm -qa`,
  `apk info -v`, `pacman -Q`) to confirm the static results. They run only inside a
  bubblewrap sandbox: a new user namespace as `nobody`, all capabilities dropped,
  `no_new_privs`, every namespace unshared (no network), nested user namespaces disabled,
  the target root read-only, a cleared environment, resource limits, timeouts with
  process-group kill and streaming output caps, after a self-test proves the identity.
  Directory targets on a same-architecture Linux host only; `--mode chroot` warns and
  `--mode auto` silently stays static when the sandbox is unavailable. Probes confirm and
  never suppress: unit-state disagreements are recorded as evidence, package-inventory
  mismatches warned, and libraries the static resolver missed added with `via: "loader"`.
  When the scanner runs as root it starts bubblewrap as host `nobody`, so the sandbox
  never maps to host root. Static remains
  the default. See `Docs/chroot-mode.md`.
- Triggers: every threat lists what activates the vulnerable code (`boot`, `socket`,
  `timer`, `cron`, `path`, `dbus`, `device`, `entrypoint`, `setuid`, `kernel`), who can
  fire it (network, local user, system, device) and the identity it runs as; a threat
  with no trigger is installed code that nothing runs. Shown in a new *Trigger* column of
  the console, Markdown and HTML threat tables.
- Cron jobs (`/etc/crontab`, `/etc/cron.d`, `/var/spool/cron{,/crontabs}`,
  `/etc/cron.{hourly,daily,weekly,monthly}`; `@reboot` counts as boot) and udev rule
  programs (`RUN+=`, `RUN{program}`, `PROGRAM`, `IMPORT{program}` with
  `/etc` > `/run` > `/usr/lib` precedence) are analysed as services. They count as
  started automatically only when an automatically started service runs a cron or udev
  daemon.
- Rolling Debian derivatives (Kali, …) without an OSV.dev ecosystem are matched against
  Debian testing (`Debian:14`) advisories as a derivative fallback, with vendor suffixes
  such as `+kali1` removed conservatively and reduced confidence;
  `--no-derivative-fallback` turns it off.
- Live dashboard for `startup-sbom scan` (on by default on a terminal, `--live/--no-live`):
  stage checklist with durations and a one-line digest per stage, and a rolling pane of
  raw operations (HTTP requests, package databases read, ELF closures, sandboxed
  commands, …). `--journal FILE` writes every stage, operation, digest and analyst note
  as JSON lines. The library API gains an `activity` callback (`ActivityEvent`).
- Live analyst (`--ai-live`, `--ai-provider`, `--ai-model`, `--ai-budget`, default
  USD 0.10; `ai` extra): a cheap model comments on each stage as it finishes, streaming
  its thinking and commentary. It has no tools, sees only stage digests and recent
  operation lines as fenced untrusted data, is display-only and never changes the report.
- The TUI scan screen shows the live stage list with digests, the raw operations log and
  a live analyst panel; the analyst is switched on in the scan settings.
- Report schema 2.2: `Threat.triggers`, `Coverage.analysis_mode`,
  `Coverage.runtime_probes`, activation `device`, init systems `cron` and `udev`.
  Reports show an *Analysis mode* line under coverage.
- Documentation is mirrored to the GitHub wiki by `tools/docs_to_wiki.py` and the
  `wiki.yml` workflow; `Docs/` stays the source of truth, so edit there, not in the wiki.

### Changed

- The 1.x entry point's `--analysis-mode chroot` now maps to the sandboxed
  `--mode chroot` instead of falling back to static analysis.
- Library closures of setuid and capability binaries are computed, so threat reversal
  knows which libraries a local user can make run as root.
- `pydantic-ai`'s start-up banner is suppressed (`PYDANTIC_AI_NO_BANNER=1` unless already
  set), so it no longer breaks the live dashboard and the TUI.

### Fixed

- Threat reversal no longer advances the attacker state on wording alone: it advances
  only when the flaw grants control or is a privilege-escalation weakness *and* something
  runs the code with more privilege (a root service, a setuid-root/capability binary that
  ships or loads it through a recorded link edge, the kernel). Installed-only code keeps
  the attacker's own privileges, and non-root services with privilege-escalation CWEs
  stop at the service account unless a privileged path exists.
- CVSS impact gate: a confidentiality-only vector (`I:N/A:N`) never yields code execution
  or privilege gain (`--no-cvss-impact-gate` disables the gate).
- Rule R5 requires a recorded link edge from a setuid/capability binary to the vulnerable
  library (or the C library/loader package `libc6`/`glibc`/`musl` when no closure was
  recorded), instead of firing whenever any setuid binary existed. On one Kali report this
  removed every chain built from a confidentiality-only flaw in an installed-only pip
  package.
- Attack-graph export (`dot`, `mermaid`): supply-chain nodes without an edge are dropped,
  packages sharing a name are told apart (e.g. Go `stdlib go1.18 (mkcert)`), and an empty
  Mermaid graph says that no attack chain or supply-chain path was found.

### Security

- CI tooling: the Codacy CLI's npm dependencies override `argparse` to `^2.0.1`, which
  removes `sprintf-js` (Dependabot alert: `sprintf-js` ≤ 1.1.3 denial of service through
  unbounded precision, no patched version).

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

[2.0.4]: https://github.com/morpheuslord/Startup-SBOM/compare/v2.0.3...v2.0.4
[2.0.3]: https://github.com/morpheuslord/Startup-SBOM/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/morpheuslord/Startup-SBOM/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/morpheuslord/Startup-SBOM/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/morpheuslord/Startup-SBOM/compare/release-1...v2.0.0
[release-1]: https://github.com/morpheuslord/Startup-SBOM/tree/release-1
