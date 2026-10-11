# Vulnerabilities and Threats

This page covers the two halves of the security analysis: **matching** — which advisories apply to the installed packages — and **reversal** — what each match means for *this* system, culminating in ranked attack chains and supply-chain findings. Matching lives in `src/startup_sbom/vulns/`, reversal in `src/startup_sbom/threat/`, and supply-chain analysis in `src/startup_sbom/supplychain/`. All of it reads only the report and bundled data files; the optional online layer is described in [Intelligence and AI](Intelligence%20and%20AI.md).

## Vulnerability sources

Sources are selected with `--sources` (default `osv,arch`); every source failure or coverage gap becomes an explicit limitation in the report, never a silent "0 vulnerabilities".

**OSV.dev** (`vulns/osv.py`) — distro-aware matching, verified against the live API:

* Distro records are indexed by **source** package (Debian, Ubuntu, Alpine, Rocky, SUSE, …), so queries use `Package.source_name` with the source version. Red Hat and AlmaLinux list *binary* names, so RPM packages are queried by both.
* The version is sent exactly as the distro writes it, epoch included; ecosystem strings come verbatim from `OSInfo.vuln_ecosystems` (e.g. `Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.20`).
* Red Hat and SLES publish per-repository/per-module streams that cannot be recovered from the package database, so those are queried by base ecosystem and the `affected` entries re-evaluated locally.
* `/v1/querybatch` returns ids only; full records are hydrated via `/v1/vulns/{id}` and cached by `(id, modified)`.

**Arch security tracker** (`vulns/arch.py`) — Arch is not in OSV. The tracker's `/issues/all.json` AVG groups are keyed by binary pkgname; a package is vulnerable iff `affected <= installed < fixed` under pacman's `vercmp`. The tracker has been effectively unmaintained since mid-2025, so every Arch scan records that as a coverage limitation and results carry medium confidence.

**NVD** (opt-in, `vulns/nvd.py`) — CPE range matching only for packages no other source covers, never a keyword search. The product-level `virtualMatchString` is queried with the installed version as a range bound and every returned CVE's configurations are re-checked locally. Distro backports are invisible to CPE data, so NVD results always carry low confidence. Enable with `--sources osv,arch,nvd` and `NVD_API_KEY`; requests are paced to NVD's published limits.

**Enrichment** — FIRST **EPSS** (daily bulk CSV preferred, so one request covers every CVE and works offline from cache; JSON API fallback chunked to its limits) and the CISA **KEV** catalog (date added, due date, ransomware use, required action). Both are cached by `startup-sbom db update` and skippable with `--no-epss` / `--no-kev`.

Records from all sources are normalised (`vulns/normalize.py`) — CVE identity extraction, CVSS parsing through the `cvss` library, severity resolution (CVSS v4 > v3.1 > v3.0 > v2 > distro rating) — and merged per CVE and package, collapsing duplicates such as Debian's `DEBIAN-CVE-*` + `DSA-*`.

### Version comparators

`vulns/versions.py` ports the reference algorithms so results are identical to the distribution tooling: dpkg `verrevcmp` (`~` ordering, epochs, revisions), `rpmvercmp` (including `~` pre- and `^` post-release, compared as `epoch:version-release`), apk-tools `apk_version_compare` (suffix ordering `_alpha < _beta < _pre < _rc < release < …`), pacman `alpm_pkg_vercmp`, PEP 440 for PyPI and a SemVer-like ordering for other language ecosystems.

## Threat reversal

`threat.reverse_vulnerabilities()` turns each vulnerability into a `Threat` grounded in what the scan observed. Where data is missing the analysis stays conservative (unknown attack vector, no privilege gain, lower score) rather than guessing.

* **Reachability** (`reachability.py`) — where the vulnerable package sits, decided only from observed facts, strongest first: `network_service`, `boot_service`, `linked_by_service`, `on_demand_service` (socket/timer/dbus), `setuid`, `kernel`, `installed`. Every classification carries a witness path, e.g. `["systemd:ssh.service", "/usr/sbin/sshd", ".../libsystemd.so.0", ".../liblzma.so.5", "pkg:deb/debian/liblzma5@5.6.1-1"]`.
* **CVSS pre/post-conditions** (`cvss.py`) — attacker pre-conditions (attack vector, privileges required, user interaction) are read from the base metrics via the `cvss` library; scores are never recomputed by hand, and a missing or unparsable vector yields "unknown". Combined with the service's run-as user, this produces the threat's `precondition` ("remote", "local:www-data") and `postcondition` ("root", …).
* **CWE consequences** (`cwe.py`) — consequence classes (code execution, privilege escalation, authentication bypass, information disclosure, tampering, DoS, supply-chain compromise) come from MITRE's *Common Consequences* data (bundled `cwe.json`), inherited from `ChildOf` ancestors in the CWE-1000 research view when the weakness lists none; the CVSS impact metrics disambiguate memory-corruption weaknesses between code execution and crashes.
* **ATT&CK** (`attack.py`) — technique mapping in priority order: CTID per-CVE mappings (KEV set + `attack_to_cve`), the CTID methodology vulnerability-type table joined to CWE, CWE → CAPEC → ATT&CK taxonomy links (capped), and finally a context-derived generic exploitation technique (T1190, T1210, T1068, T1203, T1211, T1212).
* **STRIDE** — each threat is tagged with its STRIDE categories, derived from the consequence classes and the CVSS vector facts.
* **SSVC** (`ssvc.py`) — the CISA Coordinator tree v2.0.3 (CERT/CC tables, Apache-2.0) decides Track / Track\* / Attend / Act from exploitation, automatability, technical impact and — since *Mission & Well-Being* cannot be observed in a root filesystem — the scan's observed *System Exposure* (`small`/`controlled`/`open`) as the situated proxy. The BOD 26-04 deployer timeline tree is evaluated as well; both decision paths are recorded as traces with exact flip conditions ([Intelligence and AI](Intelligence%20and%20AI.md#the-explainable-ai-layer) describes the traces).
* **Transparent risk score** (`scoring.py`, formula `risk/1`):

  ```text
  risk = 100 × likelihood × reachability × impact × privilege_gain × Π mitigations

  likelihood   = min(1, max(0.6·EPSS + 0.4·min(1, exploitability/3.887),
                            1.0 if KEV, exploit-maturity floor))
  reachability = weight of the observed execution path (network_service 1.0 … installed 0.15)
  impact       = strongest consequence class (RCE/supply-chain 1.0 … DoS 0.3)
  privilege    = 1.0 root/host, 0.6 service account, 0.3 no attacker-state change
  mitigation   = one multiplier per hardening directive that applies to this threat
  ```

  Kernel packages inside a container image are down-weighted (they are not the running kernel). The score is exactly decomposable into per-factor contributions — the decomposition machinery lives in `explain/attribution.py`.

Each threat also carries a plain-English narrative, a remediation (the fixed version when one exists), evidence ids and a weakest-link confidence.

## Attack chains

`threat/rules.py` is a forward-chaining rule set over a `FactBase` extracted from the report (threats, services, privileged binaries, the kernel, container posture, writable units, blast-radius edges). Each rule yields edges in the privilege lattice `remote → local:<user> → root → container_escape/host → persistence`:

| Rule | Edge |
|---|---|
| R1 / R2 | Remote exploit of a network-reachable service (unauthenticated / requiring an account) → foothold as its run-as user |
| R3 | Local privilege escalation to root |
| R4 | Setuid/privileged binary with a local privilege-escalation flaw |
| R5 | Library/loader flaw abused through a present setuid binary |
| R6 | Writable unit/service file → persistence or escalation |
| R7 | Kernel vulnerability exploitable by a local user |
| R8 | Dangerous ambient/file capability |
| R9 | Container escape (privileged container, mounted engine socket, …) |
| R10 | Supply-chain compromise propagating along code-loading edges |
| R11 | Persistence establishment |
| R12 | Hardening that prunes an edge or downgrades its likelihood (multiplicative) |

`threat/chains.py` takes the fixpoint of these edges from each entry state, enumerates the simple paths to the strongest reachable goal (pure Python, no graph library) and scores each chain as `100 · Π p_step · goal impact` (formula `chain/1`), exactly decomposed by LMDI into the chain's explanation. Chains are ranked, capped at `ScanOptions.max_chains` (default 25), given an SSVC decision and a step-by-step narrative, and rendered as graphs in several formats ([Outputs](Outputs.md)).

## Supply-chain analysis

`supplychain.analyze()` answers two questions:

* **Where does the code come from?** Repository provenance per package, inferred the way package managers themselves do it, from files inside the root only — apt `sources.list`/deb822 plus cached `Packages` indexes, pacman sync databases, apk indexes, rpm signature keys. Finding kinds include `third_party_repo`, `insecure_repository`, `third_party_key`, `unsigned_package`, `local_build`, `not_in_repository`, `repo_version_mismatch`, `repo_checksum_mismatch`, `unknown_signing_key`, `modified_file`, `unmanaged_binary`, `suspicious_version`, `eol_distro`, `embedded_language_packages` and `vendor_concentration`. Findings on packages that matter at boot are reported individually; the same signal elsewhere is aggregated per kind. Optional `--integrity` hashing verifies on-disk bytes against recorded package digests, prioritised by what actually runs and bounded. End-of-life status comes from endoflife.date (`--no-eol` to skip).
* **How far does an issue reach?** A vendor → source package → binary package → file → service graph built from real **code-loading edges** (`links`, `dlopens`, `interprets`, `preload`, `loads_config`) recorded by the ELF link analysis. For every vulnerable or high-risk package a confidence-weighted strongest-path search computes the **blast radius**: the services it reaches, with one example path per service — exactly the xz → liblzma → libsystemd → sshd class of chain that declared dependencies miss.

Vendor attribution normalises the most authoritative per-ecosystem field (rpm `VENDOR`, deb `Maintainer`, apk `m:`, pacman `%PACKAGER%`) so distribution teams group together and `Unknown Packager` becomes `local build`.
