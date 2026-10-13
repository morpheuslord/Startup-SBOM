# Chroot Mode

Startup-SBOM is a static analyser by default: in `--mode static` it reads files and never executes anything that belongs to the target. **Chroot mode** (`--mode chroot`) adds one pipeline stage, *Confirming with the target's own tools (sandboxed)*, which asks the target's own dynamic loader, `systemctl` and package manager to confirm what static analysis inferred. Those programs run only inside an unprivileged, read-only, network-less [bubblewrap](https://github.com/containers/bubblewrap) sandbox. `--mode auto` uses chroot mode when every precondition holds and otherwise stays static. The code lives in `src/startup_sbom/sandbox/` (`runner.py` builds and runs the sandbox, `probes.py` holds the probes) and the stage in `pipeline._chroot_probes()`.

```bash
# Confirm a mounted root filesystem with its own tools
startup-sbom scan dir:/mnt/target_root --mode chroot -f html -o out/

# Use chroot mode where possible, stay static otherwise (e.g. in a mixed CI fleet)
startup-sbom scan dir:/srv/rootfs --mode auto -f json
```

Static analysis remains the default and remains the basis of every finding. The probes confirm or correct a few specific facts; they never replace the static pipeline.

## Why it replaced the 1.x chroot mode

The 1.x "chroot" analysis bind-mounted the target's `/usr`, `/bin`, `/lib` and `/lib64` over the **host's** with `sudo`, and ran `sudo chroot <target> systemd-analyze plot` — untrusted target binaries executing as root on the host, with the host filesystem modified and never unmounted (audit findings C-2 and C-3 in the [Refactor Plan](Refactor%20Plan.md)). Version 2.0.0 removed it.

The 2.x chroot mode is a different design. It never mounts anything over the host, never uses `sudo`, and never runs anything as root: the target's tools run as `nobody` in their own namespaces, see only the read-only target root, and have no network. It also does not run `systemd-analyze`; boot timing still comes from a `systemd-analyze plot` SVG or `blame` output passed with `--boot-timing`, or from the live host in `host:` mode ([Init Systems](init-systems.md#systemd)).

The 1.x entry point maps onto it: `python3 main.py --analysis-mode chroot` now runs a 2.x scan with `--mode chroot` (previously it fell back to static analysis).

## The sandbox

Every sandboxed command is started by `Sandbox.run()` as a fixed argv list (never a shell) whose first element must be an absolute path inside the target. bubblewrap is invoked with these guarantees:

* **Unprivileged identity.** A new user namespace (`--unshare-user`) in which the program runs as `nobody` (uid/gid 65534), with **every capability dropped** (`--cap-drop ALL`) and bubblewrap's `no_new_privs`, so setuid bits and file capabilities in the target are inert.
* **Own namespaces.** `--unshare-all`: a new network namespace (no network access at all) and private pid, ipc, uts and cgroup namespaces, so the program cannot see or signal host processes.
* **No nested user namespaces** (`--disable-userns`), a common kernel-exploitation primitive.
* **Read-only target, nothing of the host.** The target root is bind-mounted read-only as `/` (`--ro-bind`). When the target has the directories, it gets a fresh `/proc`, a minimal `/dev`, and private 16 MiB tmpfs mounts at `/tmp` and `/run`. No host path is mounted.
* **Clean process state.** The environment is cleared (`--clearenv`) and set to a fixed `PATH` of the standard system directories, `LC_ALL=C`, `HOME=/nonexistent`, `SYSTEMD_PAGER=` and `SYSTEMD_COLORS=0`; the working directory is `/`; stdin is `/dev/null`. `--new-session` detaches the program from the controlling terminal (no `TIOCSTI` input injection), and `--die-with-parent` ends it if the scanner exits.
* **Resource limits** (inherited from the bubblewrap process): 30 s of CPU time, 2 GiB of address space, 16 MiB maximum file size, no core dumps.
* **Timeouts.** Every command has a wall-clock limit (10 s for the self-test and each loader query, 30 s for `systemctl`, 60 s for a package query; 20 s by default). On timeout the whole process group is killed with `SIGKILL`.
* **Output caps enforced while streaming.** stdout is capped at 4 MiB and stderr at 64 KiB as the bytes arrive; when stdout overflows, the process group is killed. Output is never buffered without bound.
* **Self-test first.** Before any probe runs, `Sandbox.self_test()` executes the target's `/bin/sh -c 'id -u …'` in the sandbox. If bubblewrap cannot create the sandbox, or the program reports any identity other than uid 65534, the sandbox is declared unavailable and no probe runs.

Everything a probe prints is untrusted text from the target. Parsers read a bounded number of lines with strict regular expressions, and a probe that fails or gives no usable answer becomes a coverage note, never a scan failure.

## Preconditions

`sandbox.open_sandbox()` checks:

| Precondition | Why |
|---|---|
| A **directory target**: `dir:PATH` or `host:` | Images and archives (`tar:`, `docker-archive:`, `oci-*`, `docker:` …) are read in place and never extracted, so there is no directory to sandbox. They are always analysed statically |
| Target CPU architecture equals the host's | Read from the ELF header of `/bin/sh`, `/usr/bin/sh`, `/bin/busybox` or `/usr/bin/env`. Foreign-architecture binaries would need emulation, which is not attempted |
| A **Linux** host | bubblewrap and user namespaces are Linux features |
| `bwrap` installed and on `PATH` | The sandbox is bubblewrap |
| **Unprivileged user namespaces** allowed, and the self-test passes | Some distributions disable or restrict them; the self-test detects this and names the reason |
| The target has `/bin/sh` or `/usr/bin/sh` | Needed to run the self-test |

The published container image does not include bubblewrap, so chroot mode inside it falls back to static analysis.

What happens when a precondition fails depends on the mode:

| `--mode` | Sandbox available | Sandbox unavailable |
|---|---|---|
| `static` (default) | not used | — |
| `chroot` | probes run | a **warning** and a coverage limitation (`chroot mode unavailable, results are from static analysis only: <reason>`); the scan continues statically |
| `auto` | probes run | the same coverage limitation, without a warning |

## The probes

Three probes run in this order. Each is isolated: an exception in one is recorded as `failed: …` and the others still run.

### `systemd` — the service manager's own verdict

When the target has `/usr/bin/systemctl` or `/bin/systemctl` and the scan found systemd units, the probe runs

```text
systemctl --root=/ list-unit-files --no-legend --no-pager --full
```

and compares each reported `.service`, `.socket`, `.timer` and `.path` state with the static result for the same unit:

* A unit `systemctl` reports as **masked** while static analysis found no mask on disk is **kept as started**; the evidence line `systemctl (chroot probe) reports masked, but no mask was found on disk; kept as started (the probe confirms, it never suppresses)` is added. No probe ever removes a service, so a hostile target cannot hide one by lying.
* Any other **enablement disagreement** is recorded as evidence only (`systemctl (chroot probe) reports <state>; static analysis had enabled=<bool>`); the static result is kept. `static`, `generated` and `transient` states never count as disagreements. `enabled`, `enabled-runtime`, `linked`, `linked-runtime`, `indirect` and `alias` count as enabled.

### `loader` — the target's dynamic loader

For every dynamically linked ELF executable the scan analysed (service executables and setuid/capability binaries), the probe runs the binary's own `PT_INTERP` loader from the target:

```text
/lib64/ld-linux-x86-64.so.2 --list /usr/sbin/sshd
```

`--list` makes the loader resolve and map the binary's libraries and print where each one came from; the program itself is not started. The loader's answer reflects its own `ld.so.cache`, hwcaps subdirectories, `$ORIGIN` and RPATH handling, which the static loader emulation ([Architecture](architecture.md)) reproduces but cannot be certain of. For each binary:

* a library already in the static closure counts as **confirmed**;
* a library the static resolver missed is **added** to the binary's `libraries` with `via: "loader"`, high confidence, depth 1 if it is a direct `DT_NEEDED` entry (2 otherwise) and its owning package;
* a library the loader reports as `not found` is added to the binary's `unresolved` list.

Binaries used by services and setuid binaries are queried first. The probe stops after **400 binaries or 120 seconds**, whichever comes first, and records how many were skipped as a coverage limitation.

Added link edges flow into everything downstream: `linked_by_service` reachability, triggers, supply-chain blast radius and rule R5 ([Vulnerabilities and Threats](vulnerabilities-and-threats.md)).

### `packages` — the package manager's inventory

For every package database the parsers read ([Package Databases](package-databases.md)) whose tool exists in the target, the probe asks the package manager for its inventory:

| Database | Command |
|---|---|
| dpkg | `dpkg-query -W -f '${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'` |
| rpm | `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'` |
| apk | `apk info -v` |
| alpm | `pacman -Q` |

The `(name, version)` pairs are compared with what the pure-Python parsers read (a `0:` epoch, dpkg architecture qualifiers and rpm `gpg-pubkey` entries are normalised away; dpkg entries that are not installed are ignored). The result goes into the stage digest — full agreement, or how many packages agree, how many only the package manager reports, and how many only the parser read. Packages that only the package manager reports also produce a **warning** naming up to five of them. The package inventory itself is not changed.

## What changes in the report

* `metadata.coverage.analysis_mode` is `"chroot"` when the sandbox opened (`"static"` otherwise) and `metadata.coverage.runtime_probes` lists the probes that ran, e.g. `["loader", "packages", "systemd"]`. Every probe that did not run adds a limitation `chroot probe <name> did not run: <reason>`.
* The console, Markdown and HTML reports show an **Analysis mode** line under coverage, e.g. `chroot (sandboxed probes: loader, packages, systemd)` ([Outputs](outputs.md)).
* Disagreements (masks, enablement) are recorded in each service's `evidence`, never applied; loader-confirmed libraries appear in `binaries[].libraries` with `via: "loader"`.
* The stage digest summarises the run, e.g. `97 sandboxed command(s); systemd: …; loader: …; packages: …`, and every sandboxed command appears as a raw operation such as `sandbox: /usr/bin/dpkg-query -W -f … → exit 0 (85 ms, 41,210 bytes)` in the live dashboard and the journal ([Live Scanning](live-scanning.md)).

As an illustration, chroot mode on one Debian-based host ran 97 sandboxed commands: `systemctl` agreed with static analysis on 134 of 136 units, the target's loader confirmed all 1,373 statically resolved library links, and `dpkg-query` agreed on all 1,115 packages.

## Limitations and residual risk

!!! warning "Chroot mode executes code from the target"
    The sandbox narrows what that code can do; it cannot make running it as safe as not running it. Static mode stays the default for that reason. Use chroot mode on targets you would be willing to run as an unprivileged user, and prefer a disposable VM for images you believe to be hostile.

* **Kernel attack surface.** The sandboxed program makes system calls to the host kernel. A kernel vulnerability — user-namespace code paths in particular — could still be used to escape. No seccomp filter is applied yet. Keep the host kernel patched.
* **Root callers are dropped first.** bubblewrap maps the sandbox's `nobody` to the uid that starts bubblewrap, so when the scanner itself runs as root (`sudo`) it starts bubblewrap as host `nobody` (uid/gid 65534, no supplementary groups). The namespace therefore never maps to host root; a kernel escape would land as `nobody`. Files only root can read are then invisible to the probes (they simply confirm less).
* **The target's tools can lie.** A compromised target controls its own loader, `systemctl` and package manager. The probes limit what a lie can do: the loader probe only adds links and unresolved names, the package probe only warns, and the `systemd` probe only records evidence. A lie can therefore add findings or notes but never remove a service, a package or a library link from the report.
* **Directory targets on the same architecture only.** Images and archives stay static, and no emulation is used for foreign architectures.
* **Bounded coverage.** The loader probe stops after 400 binaries or 120 seconds, and every probe gives up on a timeout; what was skipped is listed under coverage limitations.
* **No boot timing.** Chroot mode does not run `systemd-analyze`; use `--boot-timing`.
