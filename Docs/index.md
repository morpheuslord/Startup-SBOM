# Startup-SBOM

<p align="center">
  <img src="assets/logo.svg" alt="Startup-SBOM logo" width="140">
</p>

**What runs at boot, what it is made of, and how it can be attacked.**

Startup-SBOM is a read-only static analyser for Linux root filesystems, containers
and images. It does not stop at "which packages are installed": it maps what
actually runs at boot — through which services, as which user, exposed on which
ports — and turns that context into concrete, ranked security findings. Nothing in
the target is ever executed, mounted, extracted or modified.

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
    supervisord, inittab and container entrypoints.

-   **[Vulnerabilities and Threats](vulnerabilities-and-threats.md)**

    ---

    Advisory matching, threat reversal, SSVC decisions, attack chains and
    supply-chain blast radius.

-   **[Outputs](outputs.md)**

    ---

    Native JSON, CycloneDX, SPDX, SARIF, VEX, Markdown, HTML, PDF, DOT and
    Mermaid — plus exit codes and CI policy gates.

-   **[Intelligence and AI](intelligence-and-ai.md)**

    ---

    Online intelligence prefetch, the explainable-AI layer, and the optional
    grounded agentic layer with MCP, A2A and ACP servers.

-   **[Integration](integration.md)**

    ---

    Docker, the composite GitHub Action, pre-commit hooks, the library API and
    the published JSON Schema.

</div>
