# Startup-SBOM 2.0 — Refactor Plan

This document records the plan for the `refactoring` branch: what was wrong, how
each problem is fixed, and how the new architecture delivers the three headline
capabilities — **vulnerability → threat reversal**, **chained-attack mapping** and
**supply-chain / vendor-chain analysis**.

It was produced from nine parallel research tracks (packaging/CI, vulnerability
data, threat modelling, supply chain, package-DB formats, init systems, security
audit, output standards, image acquisition), each verified against primary
sources and live data in October 2026.

---

## 1. Fix ledger (audit finding → fix)

| ID | Finding (old code) | Fix in 2.0 |
|----|--------------------|------------|
| C-1 | `--docker <ref>` flowed into `os.path.join` + `shutil.rmtree` *before* validation → arbitrary directory deletion | Container refs validated against the moby/distribution grammar before any use; temp dirs only from `tempfile.mkdtemp`; nothing derived from user input is ever deleted |
| C-2 | "chroot" mode bind-mounted the target's `/usr`, `/bin`, `/lib`, `/lib64` **over the host's** with `sudo`, never unmounted | Removed. The tool never mounts, never uses `sudo` |
| C-3 | `sudo chroot <target> systemd-analyze plot` executed untrusted target binaries as root | Removed. Boot timing is parsed from a user-supplied `systemd-analyze plot/blame` output (`--boot-timing`) or read from the *running* host in `host:` mode only |
| C-4 | Symlinks in the target resolved against the **host** (`realpath`, `readlink`, host-path fallback) → host files leaked into SBOMs; FIFOs hang; huge files OOM | All target access goes through `RootFS`: component-wise resolution re-rooted at the image root, 40-hop budget, `O_NOFOLLOW|O_NONBLOCK`, `fstat` regular-file check, per-file read caps |
| C-5 | CVE lookup silently broken (nvdlib `delay` without key raised, swallowed → "0 CVEs"; exact-match flag inverted) | NVD keyword search removed. OSV.dev distro-aware matching by **source package + full epoch version + exact ecosystem string**; failures are surfaced as coverage limitations, never as a false all-clear |
| H-1 | `docker export \| tar -x` of untrusted archive (escapes, devices, setuid, bombs, unchecked exit codes) | No extraction. Exports/saves stream to a size-capped temp file and are read through the tar VFS; both process exit codes checked |
| H-2 | Container `Env` (secrets) written to disk inside the export | Env values never stored; only key names, with secret-looking keys flagged as redacted |
| H-3 | `--docker` crashed (`abspath(None)`), `--pkg-mgr` ignored, default `/mnt` | New CLI `startup-sbom scan <target>` with explicit schemes; legacy flags mapped by a compatibility shim |
| H-4 | `--info-graphic type=bool` (`False` → `True`) | Proper boolean flags (Typer) |
| H-5 | Substring path ownership (`/bin/sh` → coreutils) | `FileOwnerIndex`: exact, usr-merge aware, canonicalised through target symlinks |
| H-6 | dpkg status parser crashed on valueless fields; arch-qualified `.list` never matched | RFC-822 parser with continuation lines, `Status` filtering, `pkg:arch.list` support, distroless `status.d` |
| H-7 | Non-UTF-8 / binary / huge files aborted analysis | Bytes-first reading, `errors="replace"`, bounded reads, per-entry error isolation |
| H-8 | APK parser read `o:` (origin) as files → every Alpine result wrong | Full apk field support: files = `F:` dir + `R:` file, `o:` = source/origin, `Z:` checksums |
| H-9 | CVE name normalisation stripped `lib` (`libssl3` → `ssl3`) | Removed; binary → source mapping from the package DB itself |
| H-10 | CycloneDX: host distro, invalid purls, duplicate bom-refs, vulns dropped, no metadata | `cyclonedx-python-lib` 11 (spec 1.6 default, 1.5/1.7 selectable), purl-spec compliant `deb/rpm/apk/alpm` purls with `distro`/`arch`/`epoch`/`upstream` qualifiers, OS component, dependency graph, services, vulnerabilities with CVSS/EPSS/KEV, schema-validated in tests |
| H-11 | `rpm==0.1.0` shim read the **host** RPM DB; only worked on RPM hosts | Pure-Python RPM reader for sqlite, Berkeley DB (both endians) and NDB, validated against go-rpmdb fixtures and a 5 291-package real DB |
| H-12 | `rich.print` rendered untrusted strings as markup | All untrusted text escaped; console rendering separated from data |
| M-1 | Graphviz DOT/HTML-label injection, CWD output, system `dot` dependency | DOT/Mermaid emitted as escaped text with surrogate node ids; HTML report self-contained, no native dependency |
| M-2 | Non-atomic overwrite, surprise `<path>.cdx.json` | Atomic `os.replace` writes into an explicit output directory/file per format |
| M-3 | O(n²) re-reads (21 s for 3 000 packages) | Each DB parsed once into indexes |
| M-4 | Non-deterministic ordering | Canonical sorting of every list; reproducible output |
| M-5 | Docker entrypoint `IndexError`, name with `/` | Shell-form parsing via `shlex`, wrapper unwrapping (tini, dumb-init, s6, `sh -c`) |
| M-6 | Broad `except` hiding errors; tracebacks to users | Typed exceptions, per-stage isolation, `--debug` for tracebacks, warnings recorded in the report |
| L-* | Dead deps, dead code, committed scan artefacts leaking a hostname, no lockfile, weak enabled-detection | Removed artefacts, `.gitignore` for scan outputs, `uv.lock`, full systemd install/boot graph |

## 2. Architecture

```
src/startup_sbom/
  rootfs/      read-only root-confined VFS (directory + layered tar)
  sources/     target parsing & acquisition: dir, host, tar, docker-archive,
               oci-dir/oci-archive, docker:/podman:/nerdctl: containers & images
  distro.py    os-release → OS family, OSV ecosystem strings, EOL lookup key
  pkgdb/       dpkg, rpm (sqlite/bdb/ndb), apk, alpm readers; ownership index
  langpkgs/    embedded ecosystems: Python dist-info, npm, Go buildinfo, jars
  initsys/     systemd (search paths, drop-ins, masks, templates, boot graph,
               sockets, hardening exposure), SysV/LSB, OpenRC, runit, s6,
               supervisord, inittab, container entrypoint
  binaries/    ELF reader, root-confined loader emulation (DT_NEEDED, RUNPATH,
               ld.so.cache, .note.dlopen, ld.so.preload), shebangs, setuid/caps
  vulns/       OSV (online + cache), Arch tracker, NVD CPE (opt-in), EPSS, KEV,
               version comparators (dpkg/rpm/apk/alpm)
  threat/      CVSS pre/post-conditions, CWE consequences, ATT&CK mapping,
               reachability, SSVC, risk score, narratives; attack-graph engine
  supplychain/ provenance (repos, signing, unmanaged binaries, integrity), vendor
               graph, blast radius, EOL
  report/      native JSON (+ JSON Schema), CycloneDX, SPDX 2.3, SARIF 2.1.0,
               OpenVEX, CycloneDX VEX, Markdown (Mermaid), self-contained HTML,
               DOT, console
  pipeline.py  orchestration; cli.py Typer CLI; legacy shim in main.py
```

### Pipeline

1. **Acquire** target → `RootFS` (+ `ContainerInfo` for containers/images).
2. **Identify** OS from the *target's* `os-release` (resolved inside the root).
3. **Inventory** packages from every detected DB (+ language packages) and build
   the exact file-ownership index.
4. **Discover services** from every detected service manager; resolve each command
   to a canonical in-image executable (unwrapping wrappers), derive activation,
   boot path, user/capabilities/hardening and declared listeners.
5. **Link analysis**: for each service executable, ELF loader emulation inside the
   root (needed libs, dlopen notes, preload, interpreter, shebang) → library →
   package edges.
6. **Vulnerabilities**: OSV by source package & exact ecosystem; dedupe by CVE;
   enrich with EPSS + KEV; record coverage gaps explicitly.
7. **Threat reversal**: each vulnerability is placed in system context
   (reachability path, attacker precondition → postcondition from CVSS + CWE,
   run-as user, network exposure, mitigating hardening, ATT&CK techniques,
   STRIDE, SSVC decision, transparent risk score, narrative, remediation).
8. **Attack chains**: privilege-state graph
   `remote → local:<user> → root → container-escape/host → persistence` built by a
   forward-chaining rule engine from threats and misconfigurations (setuid/caps,
   writable units, docker socket, privileged container, kernel CVEs, supply-chain
   edges), pruned by hardening, ranked by likelihood × impact.
9. **Supply chain**: vendor → source → binary package → file → service graph;
   provenance findings; blast radius of each vulnerable/flagged package through
   code-loading edges (catches xz → liblzma → libsystemd → sshd).
10. **Report** in every requested format, deterministically ordered.

## 3. Security requirements (enforced by design and tests)

1. Never execute, mount, chroot or `sudo`; never write into the target.
2. All target paths resolved inside the root; refuse non-regular files; bounded reads.
3. No archive extraction; size/entry caps on archives and exports.
4. Subprocess (container engines only): absolute tool path via `shutil.which`, argv
   lists, `--` before user input, timeouts, exit codes checked.
5. Network: HTTPS allow-list, TLS verified, timeouts, retries, offline mode; API keys
   only in headers, never logged.
6. No secrets in output (env values dropped), no host identity in artefacts.
7. Output escaping for console, Markdown, HTML, DOT, SARIF.
8. Atomic writes; explicit output locations.
9. Supply chain of the tool itself: `uv.lock`, Dependabot (uv + actions), SHA-pinned
   actions, zizmor, CodeQL, `uv audit`, PyPI Trusted Publishing with PEP 740
   attestations, build provenance, signed container images with SBOM.

## 4. Packaging & distribution

* `uv` project, `uv_build` backend, `src/` layout, Python ≥ 3.11 (3.10 is EOL).
* Distribution channels: PyPI (`uvx startup-sbom`), OCI image (multi-arch,
  non-root), composite GitHub Action with SARIF upload, pre-commit hook,
  Python library API (`startup_sbom.scan()`).
* CI: ruff (incl. bandit rules), mypy strict, pytest on Linux/macOS/Windows ×
  Python 3.11–3.14, build + wheel smoke test, schema validation of all outputs.

## 5. Cross-platform support

* Host OS: everything except `host:` mode and live container acquisition is pure
  Python and works on Linux, macOS and Windows; in-image paths are POSIX strings.
* Target OS coverage: Debian/Ubuntu (dpkg incl. distroless), RHEL/Fedora/CentOS/
  Rocky/Alma/Oracle/Amazon/SUSE/Mariner (rpm sqlite/bdb/ndb), Alpine/Wolfi/
  Chainguard (apk), Arch (alpm); init systems systemd, SysV, OpenRC, runit, s6,
  supervisord, busybox inittab, container entrypoints.
* Vulnerability coverage is reported per ecosystem; unsupported distros produce an
  explicit limitation rather than a silent empty result.
