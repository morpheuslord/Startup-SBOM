# Init Systems

The point of Startup-SBOM is knowing what a system *would run* — so service-manager analysis is the heart of the scan. `initsys.discover_all()` (`src/startup_sbom/initsys/`) runs every analyser whose `detect()` matches, then reconciles the results into one coherent view: the manager that is actually **PID 1** (the container entry process when scanning a container, otherwise `/sbin/init` resolved inside the root) keeps its automatic activations, while a manager that is merely installed — or launched *by* another service, such as an `ENTRYPOINT` running `supervisord` or a systemd unit running `runsvdir` — has its activations downgraded to manual (with the reason in the service's evidence) or inherits the launching service's activation. Everything is read from configuration files only, through the root-confined VFS ([Architecture](Architecture.md)); nothing is ever executed.

All analysers share `initsys/cmdline.py`, which resolves a configured argv to the program that actually runs: `argv[0]` is canonicalised in-image (bare names through a PATH search *inside* the root) and well-known wrappers — tini, dumb-init, gosu, su-exec, s6-setuidgid, chpst, setpriv, runuser, env, nice, `sh -c "…"`, execline chain-loaders — are peeled off until the real target is reached, using a small, non-executing POSIX shell lexer.

## systemd

`initsys/systemd/` is the deepest analyser, an offline re-implementation of systemd's own loading logic:

* **Unit loading** (`loader.py`) mirrors `path-lookup.c`, `unit-file.c` and `dropin.c`: the full search path (including split-usr `/lib` before `/usr/lib`), the name map distinguishing aliases from linked units, masks (including masking by symlink to `/dev/null`), template fallback, and drop-in directories with directory order, first-basename-wins and lexicographic application.
* **Parsing** (`parser.py`) implements systemd.syntax(7): comments, continuation lines, the `extract_first_word` tokenizer for list values, `config_parse_exec()` prefixes (`-`, `+`, `!` …) and `;` separators, unit-name grammar, and the offline-resolvable subset of specifiers.
* **Boot transaction** (`boot.py`) emulates the pull-in closure of the default target (`default.target`, `initrd.target` for initrds, the compile-time fallback `graphical.target` when absent): `Wants=`, `Requires=`, `BindsTo=`, `Upholds=`, the `.wants/.requires/.upholds` directories across all names, aliases and templates, `Sockets=`, `Type=dbus` and default dependencies. Masked units are recorded and not traversed; every reached unit keeps the shortest human-readable chain (the service's `boot_path`).
* **Activation** — each service's activation set (`boot`, `socket`, `timer`, `path`, `dbus`, `manual`) and its socket units' listeners (`sockets.py`): the `Listen*=` grammar with systemd's dual-stack semantics, classified into `network`, `loopback` or `local` scope (honouring `BindToDevice=lo` and `IPAddressDeny`/`Allow` pairs).
* **Hardening** (`hardening.py`) — an offline re-implementation of `systemd-analyze security` (`analyze-security.c`): the merged, derived sandbox settings of a unit are run through the **81 weighted checks** to produce the 0.0–10.0 exposure score and its label (`PERFECT`, `SAFE`, `OK`, `MEDIUM`, `EXPOSED`, `UNSAFE`, `DANGEROUS`), plus the worst failing checks as named weaknesses. Derivation rules match systemd's (list semantics of `CapabilityBoundingSet`/`RestrictAddressFamilies`/`SystemCallFilter`, the settings implied by `DynamicUser=` and `Private*=`); syscall groups are vendored from `seccomp-util.c`. These exposure scores feed the threat scoring's mitigation multipliers ([Vulnerabilities and Threats](Vulnerabilities%20and%20Threats.md)).
* `Exec*=` lines become `Command` objects with resolved executables, the `+`-prefix (full privileges) flagged and wrappers recorded.

Boot *timing* can be attached from a user-supplied `systemd-analyze plot` SVG or `blame` output (`--boot-timing`, parsed as text with regular expressions — no XML parser touches the hostile SVG), or live when scanning `host:`.

## SysV init

`initsys/sysv.py` reads `/etc/init.d` with the `rc?.d` start links. Enablement comes from `S<NN>name` links in `rcS.d` and the default runlevel's `rcN.d` — never from the LSB `Default-Start:` header. The daemon a script launches is recovered heuristically: `start-stop-daemon --start` (`--startas`/`--exec`, `--chuid`), RHEL's `daemon [--user u] prog`, `init-d-script` and literal `DAEMON=`/`exec=` assignments, with `/etc/default/<name>` and `/etc/sysconfig/<name>` overrides applied.

## OpenRC

`initsys/openrc.py` (Alpine, Gentoo, Artix): the boot set is the services of the `sysinit` ∪ `boot` ∪ `default` runlevels (stacked runlevels followed with loop detection) plus everything they `need`/`want`, with virtual `provide` names resolved. Per service, variables are evaluated in openrc-run order — `conf.d/<base>`, `conf.d/<svc>`, `/etc/rc.conf`, then the script itself (`: ${var:=default}` only fills unset values) — to recover `command`, `command_args`, `command_user`, `capabilities` and `no_new_privs`.

## runit

`initsys/runit.py` (Void, Artix, phusion/baseimage): a service is enabled when linked into the active runsvdir and lacking a `down` file. Offline, `/run` is empty, so Void's `/var/service` chain is read from `/etc/runit/runsvdir/current` (default `…/default`). The command is the final `exec` of the `run` script with `chpst`/`setuidgid` and other wrappers unwrapped; `log/run` loggers are reported as separate services.

## s6 and s6-overlay

`initsys/s6.py` follows s6-overlay v3 stage-2 order: `/etc/cont-init.d/*` one-shots (lexical), the s6-rc services of the `user` bundle (`s6-rc.d/user/contents.d/<name>`, dependencies followed, bundles expanded), and legacy `/etc/services.d/<name>/run` longruns. Oneshot `up` files are parsed as single execline command lines. Plain s6 scan directories (`/etc/s6/sv`, s6-linux-init `run-image/service`) are read too.

## supervisord

`initsys/supervisord.py` parses `[program:x]`, `[fcgi-program:x]` and `[eventlistener:x]` sections with ConfigParser semantics (inline `;` comments require preceding whitespace; `%(here)s`, `%(program_name)s`, `%(process_num)d` expanded). `[include] files=` globs are relative to the including file and not recursive. `autostart` defaults to true; `user=` defaults to supervisord's own identity, and the daemon's own `[inet_http_server]` listeners are carried by the launching service.

## inittab

`initsys/inittab.py` handles both sysvinit and BusyBox `/etc/inittab` (`id:runlevels:action:process`): sysvinit honours the runlevel field and `initdefault`; BusyBox ignores runlevels, treats `id` as the controlling tty and falls back to its built-in default table when the file is missing. Each spawning entry becomes a service.

## Container entrypoints

`initsys/container.py` turns the image config into the entry "service": argv is `Entrypoint + Cmd` with runtime-exact semantics (a shell-form entrypoint receives the `Cmd` words as `$0 $1 …`), bare names resolved through the default OCI PATH, relative paths against `WorkingDir`, and wrappers (tini, dumb-init, `sh -c`, gosu/su-exec) unwrapped. Identity comes from `User` (empty = root) adjusted by identity-dropping wrappers; the sandbox comes from the runtime fields when scanning a live container and Docker's defaults otherwise; `ExposedPorts` become network listeners. Environment variable *values* are never recorded.

## Declared network listeners

Beyond socket activation and exposed ports, `initsys/netconf.py` reads the configuration of well-known daemons to find what they would bind: OpenSSH `sshd_config` (`Port`/`ListenAddress`, `Include`, default 22 on all addresses), nginx `listen` directives (`include` globs, the `*:80` default) and Apache `Listen` — honouring command-line overrides such as `sshd -p/-f`, `nginx -c` and `httpd -f`. These listeners are what make a service `network_exposed` and drive the SSVC exposure input.
