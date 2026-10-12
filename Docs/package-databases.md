# Package Databases

Startup-SBOM reads OS package databases with pure-Python, read-only parsers — no `dpkg`, `rpm`, `apk` or `pacman` binary is ever executed, so any database can be read on any host OS. `pkgdb.read_all()` probes every supported database (an image can legitimately carry more than one), returns records with globally unique `Package.id` values, and feeds the file-ownership index that the rest of the analysis depends on. Language-ecosystem packages embedded in the image are inventoried separately by `langpkgs`. Everything here is read through the root-confined VFS described in [Architecture](architecture.md).

## dpkg (Debian, Ubuntu and derivatives)

`pkgdb/dpkg.py` reads:

* `/var/lib/dpkg/status` — deb822 paragraphs. Only packages whose `Status` state word is `installed` or `triggers-awaited`/`triggers-pending` are reported, so `deinstall ok installed` and `hold ok installed` count while `config-files`, `not-installed`, `unpacked` and `half-*` do not.
* `/var/lib/dpkg/status.d/<pkg>` — **distroless** images (Google distroless and friends): one paragraph per file, no `Status` field (implicitly installed), with the file list taken from `<pkg>.md5sums`.
* `info/<pkg>[:arch].list` file lists, including arch-qualified names.

The parser handles continuation lines, valueless fields and non-UTF-8 bytes without aborting; per-entry errors are isolated.

## rpm (RHEL, Fedora, SUSE, Amazon, Azure Linux, …)

`pkgdb/rpm/` is a pure-Python rpmdb reader supporting all three backends, selected by magic bytes after locating the database (`%_dbpath` macro overrides first, then the well-known locations):

* **SQLite** (`rpmdb.sqlite`, rpm ≥ 4.16) — SQLite needs a real file, so the database (and a non-empty `-wal`) is streamed into a private temporary directory and opened read-only there; the hostile `-shm` cache is deliberately not copied.
* **Berkeley DB hash** (`/var/lib/rpm/Packages`) — either byte order; hash pages are scanned linearly and `H_OFFPAGE` overflow chains followed with loop protection, so bucket hashing is never needed.
* **NDB** (`Packages.db`, openSUSE/SLE 15 SP3+) — slots and `BlbS`-prefixed blobs with every offset and length validated.

Header blobs themselves are decoded by a bounds-checked parser (`header.py`) that validates every tag, offset and count, including install-time "dribble" entries overriding region entries. OpenPGP signature packets in the signature tags are decoded (`pgp.py`) just far enough to extract the issuer key id, fingerprint, algorithms and creation time. `gpg-pubkey` pseudo-packages are not reported as packages; they map signature key ids to signer names. CBL-Mariner / Azure Linux distroless images without an rpmdb are read from their container manifest.

## apk (Alpine, Wolfi/Chainguard, postmarketOS)

`pkgdb/apk.py` reads `/lib/apk/db/installed` (or `/usr/lib/apk/db/installed`): blank-line-separated records of `X:value` lines, a format shared by apk-tools 2 and 3. File lists come from `F:`/`R:` entries; digests are decoded from the `Z:` field (`Q1`+base64 SHA-1, `Q2`/`X2` SHA-256, and apk3's SHA-256-truncated-to-160-bits variant). For symlinks the recorded digest covers the link target string, not file content — the integrity checker knows this.

## alpm (Arch Linux and derivatives)

`pkgdb/alpm.py` reads `<DBPath>/local/<name>-<version>/` (default DBPath `/var/lib/pacman/`, overridable in `/etc/pacman.conf`): `desc` for metadata, `files` for root-relative paths and an optional gzipped `mtree` for per-file SHA-256 digests. Directory names are never parsed — `%NAME%` and `%VERSION%` come from `desc`. `%VALIDATION%` records how the package was verified (`pgp`, `sha256`, `none`), which feeds the provenance analysis.

## The file-ownership index

`pkgdb/ownership.py` builds the path → owning-package index everything else queries ("which package ships `/usr/sbin/sshd`?"). Databases record paths as installed (`/bin/ip`) while the file may actually live elsewhere after usr-merge (`/usr/bin/ip`), so every recorded path is indexed under its canonical parent directory plus basename, resolved through the *target's* symlinks. Matching is exact — never substring-based (the 1.x substring matcher attributed `/bin/sh` to coreutils).

## Language packages

`langpkgs/` inventories ecosystems embedded in the image, isolating failures per ecosystem (disable with `--no-language-packages`):

| Ecosystem | Source of truth |
|---|---|
| Python | `*.dist-info/METADATA` (+ `RECORD`) and `*.egg-info` under interpreter site directories, venvs in `/opt`, `/app`, `/srv`, `~/.local`; distributions owned by an OS package are still reported, marked `managed_by` |
| npm | `node_modules/[@scope/]<name>/package.json` (nested installs included), via bounded walks that skip test/fixture/example trees |
| Go | the `.go.buildinfo` ELF blob of Go executables (module path, version and full dependency list; both inline and pointer layouts) |
| Java | `META-INF/maven/<g>/<a>/pom.properties` inside `*.jar`/`*.war`/`*.ear`, read with `zipfile` in memory, nested archives one level deep within a per-archive byte budget; falls back to `MANIFEST.MF` |
| Rust | cargo-auditable's `.dep-v0` ELF section (zlib-compressed JSON, size-capped per the format's `PARSING.md`) |

When the same purl is found at several locations, each `Package.id` gets a `file_path` qualifier so ids stay unique while `Package.purl` stays unqualified.

## purl generation

`purls.py` constructs Package URLs following purl-spec / ECMA-427 plus the de-facto conventions of Syft, Grype and Trivy, so downstream scanners match correctly:

* `deb` and `alpm` keep the epoch *inside* the version (`1:2.4.47-2`);
* `rpm` puts the epoch in the `epoch` qualifier, the purl version is `version-release`, and `upstream` names the source RPM;
* `distro=<ID>-<VERSION_ID>` (just `<ID>` for rolling distros) and `upstream=<source>[@<version>]` qualifiers are added;
* qualifiers are sorted and percent-encoded by `packageurl-python`.

The purl is normally the stable `Package.id` and the bom-ref used across every output format ([Outputs](outputs.md)); it is also what vulnerability sources are queried with ([Vulnerabilities and Threats](vulnerabilities-and-threats.md)).
