# Security Policy

Startup-SBOM is a security tool: it is pointed at root filesystems and container
images that may have been built or modified by an attacker. Version 2 was rewritten
around that assumption. This document covers which versions are supported, how to
report a vulnerability, and the security model the tool guarantees.

## Supported versions

| Version | Supported |
|---|---|
| 2.x (`startup-sbom` on PyPI, `ghcr.io/morpheuslord/startup-sbom`) | Yes. Fixes ship in the latest 2.x release |
| 1.x / `release-1` (`main.py`, `sbom_manager/`) | **No.** Known critical issues (host filesystem modification, arbitrary directory deletion, execution of target binaries as root). Do not run it; upgrade to 2.x |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

1. **Preferred:** GitHub private vulnerability reporting:
   [Security → Report a vulnerability](https://github.com/morpheuslord/Startup-SBOM/security/advisories/new).
2. Alternatively, email [chiranjeevi.naidu@proton.me](mailto:chiranjeevi.naidu@proton.me).

Please include:

- the affected version (`startup-sbom version`) and how it was installed (PyPI, container, Action);
- the target type (`dir:`, `tar:`, `docker-archive:`, ...) and, if possible, a minimal
  crafted rootfs or archive that reproduces the issue (please avoid sending real system
  images that contain secrets);
- the impact you observed or expect.

We aim to acknowledge reports within **48 hours** and to agree on a disclosure timeline
with you, normally within 90 days. Fixes are released as a new 2.x version with a
GitHub Security Advisory (and a CVE where appropriate). Reporters are credited unless
they ask not to be.

## Security model

### What the tool guarantees

The scanned target (directory, archive, image or container) is **untrusted input**.

1. **No execution in the default static mode.** With `--mode static` (the default)
   nothing from the target is ever executed. In every mode the tool never mounts,
   `chroot`s, uses `sudo`, or runs `systemd-analyze` inside the target. Boot timing
   comes only from a file you supply with `--boot-timing` (or the live host in `host:`
   mode). Execution in the opt-in chroot mode is covered by item 10.
2. **Never writes to the target.** Reports are written atomically, only into the output
   directory you choose with `-o/--output`.
3. **Root-confined reads.** Every target path is resolved component by component inside
   the target root: absolute and relative symlinks are re-rooted at the image root,
   symlink chains have a hop budget, files are opened with `O_NOFOLLOW | O_NONBLOCK`,
   only regular files are read (FIFOs, devices and sockets are refused), and reads are
   size-capped. A symlink in the target cannot make the tool read a host file.
4. **No archive extraction.** `tar:`, `docker-archive:` and `oci-archive:` inputs are read
   in place through a read-only virtual filesystem with size and entry caps. Layer
   whiteouts are applied in memory.
5. **Restricted subprocesses.** The only external programs ever started are container
   engines (`docker`, `podman`, `nerdctl`) for the `docker:` / `podman:` / `nerdctl:`
   schemes, the host's own `systemd-analyze blame` for boot timing in `host:` mode, and
   bubblewrap (`bwrap`) in chroot mode (item 10). They are run with absolute paths from
   `PATH` lookup, argv lists (never a shell) and timeouts; container engines additionally
   get validated image references, `--` before user input and checked exit codes, and
   exports stream to a size-capped temporary file.
6. **Network allow-list.** HTTP is HTTPS-only with TLS verification always on, explicit
   timeouts and bounded retries, and only to these hosts:
   `api.osv.dev`, `osv-vulnerabilities.storage.googleapis.com`, `api.first.org`,
   `epss.empiricalsecurity.com`, `www.cisa.gov`, `security.archlinux.org`,
   `services.nvd.nist.gov` (only with `--sources nvd`), `endoflife.date`.
   Only package names/versions and vulnerability identifiers are sent, never file contents.
   The opt-in AI features talk to the LLM provider you configure instead (item 11).
7. **Offline mode.** With `--offline` no socket is opened at all; data comes only from
   the local cache (populate it with `startup-sbom db update`, inspect it with
   `startup-sbom db status`). Missing data is reported as a coverage limitation, never as
   "no vulnerabilities".
8. **No secret leakage.** Container environment variable *values* are never stored (only
   key names, with secret-looking keys flagged). `NVD_API_KEY` travels only in an HTTP
   header and is never logged or written to reports. Reports do not contain the scanning
   host's identity.
9. **Safe output.** Untrusted strings are escaped for the console, Markdown, HTML, DOT,
   Mermaid and SARIF; the HTML report is self-contained (no remote scripts). The live
   dashboard and the TUI sanitise every string and render it as plain text, never markup.
10. **Sandboxed execution in chroot mode.** With `--mode chroot` or `--mode auto`, the
    target's own dynamic loader (`ld.so --list`), `systemctl --root=/ list-unit-files`
    and package manager query (`dpkg-query`, `rpm -qa`, `apk info`, `pacman -Q`) are run
    to confirm static results, and only inside a bubblewrap sandbox:
    - a new user namespace, running as `nobody` (uid/gid 65534) with every capability
      dropped and `no_new_privs`, so setuid bits and file capabilities are inert;
    - all namespaces unshared (`--unshare-all`): no network, own pid/ipc/uts/cgroup;
      nested user namespaces disabled (`--disable-userns`);
    - the target root mounted read-only at `/`, a fresh `/proc`, a minimal `/dev`, small
      private tmpfs mounts at `/tmp` and `/run`; no host path is visible;
    - a cleared environment, `--new-session` (no terminal input injection),
      `--die-with-parent`, stdin `/dev/null`;
    - resource limits (30 s CPU, 2 GiB address space, 16 MiB file size, no core
      dumps), a wall-clock timeout per command with process-group kill, and stdout /
      stderr caps (4 MiB / 64 KiB) enforced while streaming;
    - a self-test that proves the sandboxed program runs as `nobody` before any probe.

    Chroot mode runs only for directory targets (`dir:`, `host:`) whose CPU architecture
    matches a Linux host with `bwrap` and unprivileged user namespaces. Images and
    archives are never extracted, so they are always analysed statically. If a
    precondition fails, `--mode chroot` warns and `--mode auto` silently falls back to
    static analysis; both record the reason as a coverage limitation. Probe output is
    parsed as untrusted text with bounded parsers.
11. **Live analyst data flow.** `--ai-live` (opt-in, `ai` extra, refused with
    `--offline`) sends data to the LLM provider you configured, and nowhere else. Per
    pipeline stage it sends the stage title, the stage digest (a summary sentence and
    its key numbers, which can include service ids, executable paths, package names and
    vulnerability ids) and at most the 12 most recent raw-operation lines (for example
    file paths, package-database names, the host and path of vulnerability lookups and
    sandboxed command lines), cleaned, size-capped and fenced as untrusted data, plus the
    analyst's earlier conversation in the same scan. It never sends file contents,
    container environment values or the report itself. The analyst has no tools, its
    output is display-only and never written into the report, and `--ai-budget` (default
    USD 0.10) caps its spend.

### What it does not protect against

- **Chroot mode runs code from the target.** The sandbox narrows what that code can do;
  it cannot make running it as safe as not running it. The sandboxed program still makes
  system calls to the host kernel, so a kernel vulnerability (user-namespace code paths
  in particular) could allow an escape, and no seccomp filter is applied yet. When the
  scanner runs as root it starts bubblewrap as host `nobody`, so an escape would not land
  as root. A compromised target also controls the tools that answer the probes, so the
  probes only confirm or add evidence and never remove a service, package or library
  from the report. Keep the default static mode for targets you consider hostile, or
  scan them in a disposable VM.
- **The `--journal` file** is created owner-only (0600) with sanitised messages, but it
  describes the scanned system in report-level detail: store it privately.

- **`host:` mode** reads the running system you invoke it on, with your privileges.
  That is by design; run it as an unprivileged user when possible.
- **Container engines.** `docker:NAME` / `podman:NAME` / `nerdctl:NAME` talk to the engine
  you have access to. Access to the Docker socket is root-equivalent on the host. Prefer
  scanning `docker save` / `docker export` archives (`docker-archive:` / `tar:`) in CI.
- **Resource exhaustion** beyond the built-in caps on extremely large inputs. Run scans of
  untrusted images with normal CI time and memory limits.
- **Accuracy.** Missed or incorrect vulnerability matches are bugs, and you can report
  them as normal issues. A silent "all clear" caused by a failed data source is a
  security bug, so report that privately.

### Running the container image safely

```sh
docker run --rm --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -v /path/to/rootfs:/target:ro -v "$PWD/out:/out" --user "$(id -u):$(id -g)" \
  ghcr.io/morpheuslord/startup-sbom scan dir:/target --offline -o /out
```

The image runs as an unprivileged user (uid 65532) and does not need the Docker socket.
Add `--user 0` only when the mounted rootfs contains root-only files; keep the target
mount `:ro`. Drop `--network none` and `--offline` to allow vulnerability lookups.

## Supply chain of Startup-SBOM itself

- Dependencies are locked in `uv.lock`. CI audits them (`uv audit`), and Dependabot proposes
  grouped weekly updates with a 7-day cooldown.
- All GitHub Actions are pinned to full commit SHAs. Workflows run with least-privilege
  tokens, are linted by zizmor, and are analysed by CodeQL.
- PyPI releases are published with **Trusted Publishing** (no long-lived tokens) and carry
  **PEP 740** attestations, plus GitHub build-provenance attestations:
  `gh attestation verify <file> -R morpheuslord/Startup-SBOM`.
- Container images are multi-arch, non-root, and ship BuildKit SBOM and provenance plus a
  Sigstore-signed attestation:
  `gh attestation verify oci://ghcr.io/morpheuslord/startup-sbom:<version> -R morpheuslord/Startup-SBOM`.
- Every GitHub release includes a CycloneDX SBOM of the tool's own runtime dependencies.
