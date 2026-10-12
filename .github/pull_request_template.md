## Summary

<!-- What does this change and why? Link issues with "Fixes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New feature (package DB, init system, source scheme, report format, threat rule, ...)
- [ ] Refactor / performance
- [ ] Documentation
- [ ] Build / CI / packaging

## Checklist

- [ ] `uv run pre-commit run --all-files` passes (ruff, ruff-format, mypy, `uv lock --check`, zizmor)
- [ ] `uv run pytest -m "not network"` passes; new behaviour has tests (fixtures built in-test, not real system dumps)
- [ ] Dependency changes were made with `uv add` / `uv remove` and `uv.lock` is committed
- [ ] `CHANGELOG.md` has an entry under **Unreleased** for user-visible changes
- [ ] Output changes keep the JSON schema / CycloneDX / SPDX / SARIF outputs valid and deterministic

## Security model (required for changes touching target access, acquisition, network or output)

- [ ] Target files are only read through `RootFS` (no host `open`/`realpath`/`readlink` on target paths)
- [ ] Nothing in the target is executed, mounted, extracted or written; no `sudo`/`chroot`
- [ ] Subprocesses (container engines only) use argv lists, absolute tool paths, `--` before user input, timeouts and checked exit codes
- [ ] Network access goes through `startup_sbom.net` (HTTPS allow-list, honours `--offline`); no secrets logged or written
- [ ] Untrusted strings are escaped for every output format (console, Markdown, HTML, DOT/Mermaid, SARIF)
- [ ] Not applicable

## Notes for reviewers

<!-- Anything that needs special attention, follow-ups, screenshots of reports, etc. -->
