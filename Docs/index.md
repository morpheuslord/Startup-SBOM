# Startup-SBOM

<p align="center">
  <img src="assets/logo.svg" alt="Startup-SBOM logo" width="140">
</p>

**What runs at boot, what it is made of, and how it can be attacked.**

Startup-SBOM is a read-only static analyser for Linux root filesystems, containers
and images. It does not stop at "which packages are installed": it maps what
actually runs at boot — through which services, timers, cron jobs and device
rules, as which user, exposed on which ports — and turns that context into
concrete, ranked security findings. Nothing in the target is ever mounted,
extracted or modified, and in the default static mode nothing is executed.

!!! tip "Latest release: 2.0.4"
    **2.0.4** is a security release: it ships patched certifi, fastmcp-slim and authlib.
    If you installed with pip or `uv tool`, upgrade the dependencies too
    (`uv tool upgrade startup-sbom`).

    **2.0.3** lists the [GitHub Action](integration.md#github-action) on the GitHub
    Marketplace as *Startup-SBOM Scan*, and `uses: morpheuslord/Startup-SBOM@v2` now
    resolves to the latest 2.x release.

    **2.0.2** is a bug-fix release: the live analyst no longer stops with an error on
    Claude Haiku, and re-running a release no longer fails or re-publishes what already
    exists.

    **New in 2.0.1:**

    * **[Chroot mode](chroot-mode.md)**: `--mode chroot` confirms the static results with the
      target's own loader, `systemctl` and package manager, run only inside an unprivileged,
      read-only, network-less bubblewrap sandbox.
    * **Triggers**: every threat says what activates the vulnerable code, who can fire it and
      as which user; cron jobs and udev rules are new trigger sources, and code nothing runs
      can no longer be reported as a path to root
      ([Vulnerabilities and Threats](vulnerabilities-and-threats.md)).
    * **[Live scanning](live-scanning.md)**: a live dashboard of stages, findings and raw
      operations, a `--journal`, and an optional LLM analyst commenting on each stage.
    * Rolling Debian derivatives such as Kali are matched against Debian testing advisories.

    The full list is in the [changelog](https://github.com/morpheuslord/Startup-SBOM/blob/main/CHANGELOG.md).

## Three questions most SBOM tools can't answer

<div class="grid cards" markdown>

-   :material-bug-check:{ .lg .middle } **Vulnerability → threat reversal**

    ---

    Not "openssl has 14 CVEs", but *"an unauthenticated remote attacker who can
    reach TCP/22 could exploit CVE-2024-6387 in `ssh.service`, enabled at boot,
    running as root"* — with EPSS, KEV, MITRE ATT&CK, systemd-hardening
    mitigations and a CISA SSVC decision on every finding.

    [:octicons-arrow-right-24: Vulnerabilities and Threats](vulnerabilities-and-threats.md)

-   :material-source-branch:{ .lg .middle } **Chained attacks**

    ---

    A privilege-state attack graph (`remote → local:<user> → root → container
    escape → persistence`) built from vulnerabilities *and* misconfigurations,
    pruned by observed hardening and ranked by likelihood × impact.

    [:octicons-arrow-right-24: Attack chains](vulnerabilities-and-threats.md#attack-chains)

-   :material-graph-outline:{ .lg .middle } **Supply-chain blast radius**

    ---

    A vendor → source package → binary package → file → service graph built from
    real code-loading edges (ELF `DT_NEEDED`, `.note.dlopen`, preload,
    interpreters). It catches the xz → liblzma → libsystemd → sshd class of
    problem that declared dependencies miss.

    [:octicons-arrow-right-24: Supply-chain analysis](vulnerabilities-and-threats.md#supply-chain-analysis)

</div>

## Install

```bash
uv tool install startup-sbom        # or: pipx install startup-sbom
uvx startup-sbom --help             # run once without installing
docker run --rm ghcr.io/morpheuslord/startup-sbom --help
```

Then point it at anything:

```bash
startup-sbom scan dir:/mnt/target_root -f html -f cyclonedx -o out/
startup-sbom scan docker-archive:./image.tar -f sarif --fail-on act
startup-sbom scan tar:./rootfs.tar.zst --offline -f json
```

Python ≥ 3.11 on Linux, macOS or Windows. Everything except `host:` mode and live
container acquisition is pure Python and host-OS independent.

## Built for hostile input

The scanned target is treated as **untrusted input**: every read goes through a
root-confined virtual filesystem with `openat2(RESOLVE_IN_ROOT)` semantics,
archives are indexed in place rather than extracted, network access is an HTTPS
allow-list that `--offline` disables entirely, and every gap in vulnerability
coverage is reported instead of silently returning "0 vulnerabilities".

Two modes, one report: **static** (the default) only reads files; opt-in
**chroot mode** (`--mode chroot`) also asks the target's own loader, `systemctl`
and package manager to confirm the static results, running them only inside an
unprivileged, read-only, network-less sandbox ([Chroot Mode](chroot-mode.md)).
While a scan runs, a live dashboard shows each stage, what it found and the raw
operations behind it, optionally narrated by an LLM ([Live Scanning](live-scanning.md)).

## Where to go next

<div class="grid cards" markdown>

-   **[Introduction](introduction.md)**

    ---

    What the tool answers, the design principles, and a quick tour of the CLI,
    target schemes and typical invocations.

-   **[Architecture](architecture.md)**

    ---

    The scan pipeline, the module map, the single canonical `Report` model and
    the security posture that confines every read.

-   **[Package Databases](package-databases.md)**

    ---

    Pure-Python readers for dpkg, rpm, apk and alpm, the file-ownership index,
    language-ecosystem packages and purl generation.

-   **[Init Systems](init-systems.md)**

    ---

    systemd (incl. offline hardening scores), SysV, OpenRC, runit, s6,
    supervisord, inittab, container entrypoints, cron and udev.

-   **[Vulnerabilities and Threats](vulnerabilities-and-threats.md)**

    ---

    Advisory matching, threat reversal, triggers, SSVC decisions, attack
    chains and supply-chain blast radius.

-   **[Chroot Mode](chroot-mode.md)**

    ---

    Opt-in confirmation of static results by the target's own tools, inside
    an unprivileged bubblewrap sandbox — guarantees, preconditions and limits.

-   **[Outputs](outputs.md)**

    ---

    Native JSON, CycloneDX, SPDX, SARIF, VEX, Markdown, HTML, PDF, DOT and
    Mermaid — plus exit codes and CI policy gates.

-   **[Live Scanning](live-scanning.md)**

    ---

    The live dashboard, raw operations, the JSON-lines journal and the
    optional live analyst.

-   **[Intelligence and AI](intelligence-and-ai.md)**

    ---

    Online intelligence prefetch, the explainable-AI layer, and the optional
    grounded agentic layer with MCP, A2A and ACP servers.

-   **[Integration](integration.md)**

    ---

    Docker, the composite GitHub Action, pre-commit hooks, the library API and
    the published JSON Schema.

</div>
