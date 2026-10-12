# Outputs

Every output format renders from the same canonicalised `Report` model ([Architecture](architecture.md)), so SBOMs, SARIF, VEX documents and human reports always agree on severity, reachability and identifiers. Formats are selected with repeatable `-f/--format` flags; `-o DIR` chooses the output directory (default `./startup-sbom-out`) and `-o -` streams exactly one format to stdout (including binary PDF). The renderer code lives in `src/startup_sbom/report/`.

## Formats

| `--format` | Default file | Contents |
|---|---|---|
| `json` | `report.json` | The complete native report, validating against the versioned JSON Schema printed by `startup-sbom schema` |
| `cyclonedx` | `sbom.cdx.json` | CycloneDX 1.5 / 1.6 (default) / 1.7 (`--cdx-spec`), built with cyclonedx-python-lib |
| `spdx` | `sbom.spdx.json` | SPDX 2.3 JSON document |
| `sarif` | `results.sarif` | SARIF 2.1.0 for GitHub code scanning and other SARIF viewers |
| `openvex` | `vex.openvex.json` | OpenVEX 0.2.0 |
| `cdx-vex` | `vex.cdx.json` | Standalone CycloneDX VEX with BOM-Links |
| `markdown` | `report.md` | GitHub-flavoured Markdown with Mermaid attack-chain diagrams |
| `html` | `report.html` | Self-contained, offline, interactive HTML report |
| `dot` | `attack-graph.dot` | Graphviz attack / blast-radius graph |
| `mermaid` | `attack-graph.mmd` | Mermaid attack / blast-radius graph |
| `pdf` | `report.pdf` | Typst-rendered PDF (optional extra `startup-sbom[pdf]`) |

Without `-o -`, a Rich console summary is printed as well (`report/console.py`); suppress it with `--quiet`. All files are written atomically.

**CycloneDX** follows what Trivy, Syft/Grype and Dependency-Track consume: exactly one `operating-system` component with dependency edges to every package, purls as bom-refs, services as CycloneDX services with endpoints, and vulnerabilities carrying CVSS ratings, CWEs and EPSS/KEV properties. Threats and attack chains stay in the native report, linked through a `threat-model` external reference.

**SPDX** is deliberately a pure inventory — the OS, the container and every package with purl/CPE external refs and `CONTAINS`/`DEPENDS_ON` relationships — because services and threats have no SPDX 2.3 equivalent.

**SARIF** emits one rule per vulnerability id plus one rule per attack-chain and supply-chain finding kind. Results point at in-image paths relative to `ROOTFS` and carry a stable `primaryLocationLineHash` (the analysed filesystem is not part of the repository). GitHub's limits — 25 000 results/rules per run, 20 tags per rule, 1 000 locations per result — are respected.

**VEX** is conservative by design: "not observed on an execution path" is not proof of "not affected" (cron jobs, login shells, `dlopen`, files parsed by other processes are not fully visible to static analysis). Installed-only vulnerabilities are therefore `under_investigation`; the operator can opt in to `not_affected` with justification `vulnerable_code_not_in_execute_path` via `--vex-unreachable-not-affected`, but KEV-listed vulnerabilities never are. The CycloneDX VEX variant is an independent document whose `affects` refs are BOM-Links (`urn:cdx:<serial>/<version>#<bom-ref>`), which is what Trivy requires and what Dependency-Track ingests via `PUT /api/v1/vex`.

**Markdown** renders on GitHub, in PR comments and in Actions job summaries; Mermaid attack graphs render natively on GitHub. Every string from the scanned system is neutralised against Markdown/HTML injection, table pipes and `@`-mentions.

**HTML** is a single file that works offline: the stylesheet and script are inlined and authorised by SHA-256 hashes under a `default-src 'none'` Content-Security-Policy, so the page makes no network requests and injected markup could not execute even if escaping failed. Tables render server-side (readable without JavaScript); the script adds sorting, filtering and an interactive SVG attack-graph / blast-radius view.

**`dot` / `mermaid`** export the combined attack graph and supply-chain blast-radius graph: privilege states as nodes, attack steps as labelled edges, with surrogate node ids and escaped labels so names from the scanned system can never inject graph syntax.

## PDF

The PDF renderer (`report/pdf/`, optional extra `startup-sbom[pdf]`) converts the report into a sanitised JSON view model and lays it out with bundled Typst templates that never interpret data as markup. Compilation uses the `typst` Python package, falling back to the official Typst CLI; neither backend downloads anything, and the template directory is the compile root so Typst `read()` cannot reach scan output or host files.

Three profiles exist (`PdfOptions.profile`):

| Profile | Standards |
|---|---|
| `archival` (default) | PDF/A-3u **and** tagged PDF/UA-1 — A-3u is what permits embedding the data attachments |
| `accessible` | tagged PDF/UA-1 only |
| `plain` | no standards profile |

By default the complete `report.json` — and the AI assessment, when present — are embedded in the PDF as file attachments, so the human document carries its own machine-readable data. Bytes are deterministic for a given report. If the strict profiles refuse glyphs the bundled fonts lack (e.g. CJK names in CVE credits), rendering retries once as a plain PDF.

## Exit codes and policy gates

Exit codes are stable and designed for CI:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | The `--fail-on` threshold was reached |
| `2` | Usage or target error |
| `3` | Internal error (re-run with `--debug` for the traceback) |

`--fail-on` accepts two kinds of threshold:

* **Severity** — `low`, `medium`, `high`, `critical`: exit 1 when any *active* vulnerability (status `affected`, `no_fix_available` or `under_investigation` — fixed and not-affected ones never trigger) reaches the level.
* **SSVC decision** — `attend` or `act`: exit 1 when any threat's SSVC decision is Act (or Attend, for `--fail-on attend`). This gates on *contextual* urgency rather than raw severity: a critical CVE in an unreachable package will not fail the build, while a medium one in a network-exposed root service may.

Reports are always written before the policy gate is applied, so CI artefacts (and the SARIF upload in the [GitHub Action](integration.md)) survive a failing gate.
