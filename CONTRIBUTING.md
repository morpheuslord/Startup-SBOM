# Contributing to Startup-SBOM

Thanks for your interest in Startup-SBOM. Bug reports, new package-database or
init-system support, better threat rules and documentation fixes are all welcome.
Please read the [Code of Conduct](CODE_OF_CONDUCT.md) and, for anything
security-sensitive, [SECURITY.md](SECURITY.md) before you start.

## Development setup

The project is managed with [uv](https://docs.astral.sh/uv/) (0.11 or newer; CI
uses 0.13.0). uv installs the right Python for you.

```sh
# install uv: https://docs.astral.sh/uv/getting-started/installation/
git clone https://github.com/morpheuslord/Startup-SBOM
cd Startup-SBOM
uv sync                                   # creates .venv with the dev, test and lint groups
uv run pre-commit install --install-hooks # ruff, ruff-format, mypy, uv lock --check, zizmor
uv run startup-sbom --help
```

Everyday commands:

| Task | Command |
|---|---|
| Run the CLI from source | `uv run startup-sbom scan dir:/path/to/rootfs --offline -o out/` |
| Tests (no network) | `uv run pytest -m "not network"` |
| Tests with coverage | `uv run pytest --cov` |
| Network tests (live OSV etc.) | `uv run pytest -m network` |
| A specific Python | `uv run --python 3.11 pytest` |
| Lint / autofix | `uv run ruff check --fix .` |
| Format | `uv run ruff format .` |
| Type check (strict) | `uv run mypy` |
| All hooks on all files | `uv run pre-commit run --all-files` |
| Build sdist + wheel | `uv build` |
| SBOM of our own dependencies | `uv export --format cyclonedx1.5 --no-dev -o deps.cdx.json` |
| Container image | `docker build -t startup-sbom:dev .` |

### Dependencies

- Add or remove dependencies with `uv add <pkg>` / `uv remove <pkg>` (use
  `--group test|lint|dev` for development-only tools) and commit the updated
  `uv.lock`. CI runs `uv lock --check` and `uv sync --locked`, so a stale lockfile fails.
- Keep runtime dependencies pure Python or with full wheel coverage (Linux, macOS,
  Windows, x86_64 and arm64, newest CPython). Avoid native-only packages.
- Dependabot opens grouped weekly updates with a 7-day cooldown.

## Project layout

```
src/startup_sbom/
  rootfs/      read-only, root-confined VFS (directory + layered tar)
  sources/     target parsing and acquisition (dir, host, tar, docker-archive, oci-*, engines)
  pkgdb/       dpkg, rpm, apk, alpm readers and the file-ownership index
  initsys/     systemd, SysV, OpenRC, runit, s6, supervisord, inittab, entrypoints
  binaries/    ELF reader and loader emulation
  vulns/       OSV, Arch, NVD, EPSS, KEV, version comparators
  threat/      threat reversal and attack-graph engine
  supplychain/ provenance, vendor graph, blast radius, EOL
  report/      JSON, CycloneDX, SPDX, SARIF, VEX, Markdown, HTML, DOT, Mermaid
  cli.py       Typer CLI
tests/         pytest suite; fixtures are generated in-test (tests/fsbuilder.py)
```

## Security rules for code changes

Startup-SBOM treats every scanned filesystem as hostile. Pull requests that touch
target access, acquisition, networking or output must keep these invariants (they
are enforced by review, ruff's bandit rules, banned-API checks and tests):

1. **Never execute, mount, chroot, `sudo` or write into the target.**
2. Read target files only through `RootFS`; never call host `open`, `os.path.realpath`,
   `readlink` or `Path.resolve` on in-image paths. In-image paths are POSIX strings
   handled with `posixpath`.
3. Never extract archives (`tarfile.extractall` is banned); never unpickle; never parse
   untrusted XML with `minidom`.
4. Subprocesses are allowed only for container engines: absolute path from
   `shutil.which`, argv lists, `--` before user input, timeouts, checked exit codes.
5. All HTTP goes through `startup_sbom.net` (HTTPS allow-list, TLS verified, honours
   `--offline`). New data sources must be added to the allow-list deliberately.
6. Escape untrusted strings for every output format; keep output deterministic.
7. Never write secrets or host identity into reports.

If you find a way to break one of these, please report it privately (see SECURITY.md)
instead of opening a public issue.

## Tests

- Every bug fix comes with a regression test; every new parser comes with fixtures that
  cover malformed input (truncated files, non-UTF-8, huge values, symlink loops).
- Build fixture filesystems in `tmp_path` with `tests/fsbuilder.py`; do not commit dumps
  of real systems. Tests that need real symlinks or POSIX permissions should skip on
  Windows rather than fail.
- Tests needing the internet are marked `@pytest.mark.network` and are excluded in CI.
- CI runs the suite on Linux, macOS and Windows with Python 3.11 to 3.14 (3.15 is
  experimental), plus an end-to-end scan of exported Debian, Alpine and Rocky Linux images.

## Pull requests

1. Fork, create a topic branch from `main`, and keep the change focused.
2. Make sure `uv run pre-commit run --all-files` and `uv run pytest -m "not network"` pass.
3. Add an entry under **Unreleased** in [CHANGELOG.md](CHANGELOG.md) for user-visible
   changes.
4. Fill in the pull request template, including the security-model checklist.

Issues and ideas are welcome too: explain the problem you are trying to solve and why it
matters to users. If you would like to add support for another package manager, init
system or image format, open an issue or a discussion first so we can agree on the design.

## Releasing (maintainers)

1. `uv version --bump minor` (or `major` / `patch`, or `--bump rc` for a pre-release).
2. Move the **Unreleased** entries in `CHANGELOG.md` under a `## [X.Y.Z] - YYYY-MM-DD`
   heading and update `version` / `date-released` in `CITATION.cff`.
3. Merge to `main`, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The `Release` workflow verifies the tag matches `pyproject.toml`, builds once, attests,
   publishes to PyPI via Trusted Publishing (approval required on the `pypi` environment)
   and creates the GitHub release with the dists and a dependency SBOM. The `Container`
   workflow publishes the signed multi-arch image to `ghcr.io/morpheuslord/startup-sbom`.
