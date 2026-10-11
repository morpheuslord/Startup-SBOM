# Introduction

Startup-SBOM statically analyses a Linux root filesystem, container or image and answers questions ordinary SBOM tools cannot: not just *which* packages are installed, but which of them actually run at boot, through which services, as which user, exposed on which ports — and what an attacker could do about it. This page explains the questions the tool answers, the design principles behind it, and gives a quick tour of the command line. The deeper material lives in the other documents: [Architecture](Architecture.md), [Package Databases](Package%20Databases.md), [Init Systems](Init%20Systems.md), [Vulnerabilities and Threats](Vulnerabilities%20and%20Threats.md), [Outputs](Outputs.md), [Intelligence and AI](Intelligence%20and%20AI.md) and [Integration](Integration.md).

## What the tool answers

**Vulnerability → threat reversal.** A CVE list says what is broken; it does not say what is at risk *on this system*. Startup-SBOM places every matched vulnerability into the scanned system's context: is the vulnerable code reachable at boot, through which service, linked by which binary, running as which user, listening on which addresses, mitigated by which systemd hardening? Each vulnerability becomes a `Threat` with attacker pre- and post-conditions ("a remote attacker who can reach TCP/22 gains root"), consequence classes, MITRE ATT&CK techniques, STRIDE categories, a CISA SSVC decision (Track / Track\* / Attend / Act) and a transparent, exactly decomposable 0–100 risk score. See [Vulnerabilities and Threats](Vulnerabilities%20and%20Threats.md).

**Chained attacks.** Single findings understate risk when they compose. A forward-chaining rule engine (rules R1–R12) derives edges in the privilege lattice `remote → local:<user> → root → container escape / host → persistence` from vulnerabilities *and* misconfigurations — setuid and capability binaries, privileged containers, mounted engine sockets, kernel CVEs, writable units — prunes and downgrades them by observed hardening, and enumerates ranked attack chains scored by likelihood × impact.

**Supply-chain blast radius.** A vendor → source package → binary package → file → service graph built from real code-loading edges (ELF `DT_NEEDED` closures, `.note.dlopen`, `/etc/ld.so.preload`, script interpreters), not from declared package dependencies. This catches the xz → liblzma → libsystemd → sshd class of problem. Provenance analysis flags third-party repositories, unsigned or locally built packages, unmanaged binaries, modified files and end-of-life distributions.

## Design principles

* **Read-only, always.** Nothing in the target is ever executed, mounted, chrooted, extracted or modified, and `sudo` is never used. The 1.x "chroot" mode, which bind-mounted the target over the host and ran target binaries as root, is gone (see [`Refactor Plan.md`](Refactor%20Plan.md) for the full fix ledger).
* **Root-confined virtual filesystem.** Every analyser reads the target exclusively through the `RootFS` abstraction, which resolves symlinks against the *image* root with the semantics of `openat2(RESOLVE_IN_ROOT)`: absolute link targets re-root at the image root, `..` can never climb above it, and loops are bounded. Host files can never leak into a report.
* **No extraction.** Tarballs, image archives and OCI layouts are indexed header-only and read in place by seeking; compressed layers are decompressed exactly once into a size-budgeted private workspace. Setuid bits, ownership and file capabilities survive for analysis, and no hostile archive member can escape.
* **Offline-first with caching.** Vulnerability feeds (KEV, EPSS, OSV, …) are cached on disk with TTL and ETag revalidation; `--offline` guarantees no socket is ever opened and serves fresh-or-stale cache only. `startup-sbom db update` pre-populates the cache for air-gapped use. Network access, when allowed, is HTTPS-only to an explicit host allow-list with TLS verification always on.
* **No silent all-clear.** Every gap — a distribution OSV does not cover, a failed source, missing cached data — is recorded as a coverage limitation in the report, so "no data" is never presented as "no vulnerabilities".

## Quick tour of the CLI

```console
$ startup-sbom --help
```

| Command | Purpose |
|---|---|
| `scan TARGET` | Analyse a root filesystem, image or container and write reports |
| `db update` / `db status` / `db clear` | Manage the cached vulnerability intelligence (KEV, EPSS feeds) |
| `schema` | Print the JSON Schema of the native report |
| `version` | Print the version |
| `tui` | Interactive terminal UI for scanning and browsing results (extra `startup-sbom[tui]`) |
| `intel lookup CVE…` / `intel update-index` | Standalone CVE intelligence lookup and exploit-index refresh |
| `ai analyze` / `agents` / `providers` / `mcp` / `serve` | AI analysis, MCP server and agent endpoints (extra `startup-sbom[ai]`) |

The `intel` and `ai` sub-commands are mounted only when their modules are installed.

### Target schemes

The `scan` argument selects what to analyse. A bare existing path is auto-detected.

```text
dir:<path>            host directory / mounted disk
host:                 the running Linux host /
tar:<file>            flattened rootfs tarball (docker export, debootstrap …; gz/xz/bz2/zstd)
docker-archive:<p>    docker/podman save (file or directory; legacy or Docker >= 25)
oci-dir:<dir>         OCI image layout directory
oci-archive:<file>    OCI image layout tarball
docker:<ref>          live engine: container first, then image (also podman:, nerdctl:)
docker-container:<c>  container only (also podman-/nerdctl-container:, container:)
```

Live-engine targets go through the engine *CLI* (never the socket), so Docker contexts, Docker Desktop, rootless engines and podman machine all behave the same; multi-platform images are selected with `--platform`, e.g. `linux/arm64`.

### Typical invocations

```bash
# A mounted disk or extracted rootfs, HTML + CycloneDX output
startup-sbom scan dir:/mnt/target_root -f html -f cyclonedx -o out/

# A container image without any engine installed
startup-sbom scan oci-archive:image.tar -f sarif --fail-on act

# The machine you are on
sudo startup-sbom scan host: -f markdown

# Air-gapped: refresh the cache elsewhere, then
startup-sbom scan tar:rootfs.tar.zst --offline -f json
```

Exit codes are stable: `0` success, `1` the `--fail-on` threshold was reached, `2` usage or target error, `3` internal error. The full flag reference is in the [README](../README.md); every output format is described in [Outputs](Outputs.md).
