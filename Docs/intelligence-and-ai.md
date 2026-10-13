# Intelligence and AI

Three layers sit on top of the deterministic scan: an opt-in **online intelligence prefetch** (`src/startup_sbom/intel/`), a built-in **explainable-AI layer** that makes every verdict auditable (`explain/`, visualised by `viz/`), and an optional **agentic AI layer** (`ai/`, extra `startup-sbom[ai]`) that reads a finished report through guarded tools — plus, in the same extra, a **live analyst** that narrates a scan while it runs. The deterministic report always stays the source of truth; nothing in these layers can silently change a finding.

## Online intelligence prefetch

`startup-sbom scan --prefetch-intel` (or the standalone `startup-sbom intel lookup CVE…`) fetches advisories, exploit availability and write-ups for the top findings, within a time budget (`--intel-budget`, default 120 s) and caps (`--intel-max-cves`, `--intel-max-articles`; `--no-intel-articles` keeps it to structured feeds only). Results are cached on disk (`intel/store.py`: bundles 24 h, articles 7 d, atomic writes, raw HTML never stored) and attached to the report as `IntelBundle` objects.

**Structured sources first** (all through the allow-listed `HttpClient`): CVE Services (cveawg.mitre.org, including CISA Vulnrichment/ADP SSVC values), NVD, GitHub security advisories, Ubuntu and Red Hat vendor APIs (queried only when the target OS makes them relevant), EPSS score trends, the Exploit-DB / Metasploit / nuclei-templates exploit indexes and PoC-in-GitHub repository metadata (metadata only — PoC repositories are never cloned or executed). **Only structured sources may change `exploitation` / `exploit_maturity`**; article text only annotates. After prefetch, threats are re-reversed: fresh evidence of a public PoC or active exploitation can *raise* SSVC exploitation and risk, never lower them. Missing data is recorded in `IntelBundle.errors` and as scan limitations, never presented as "no exploit exists".

**SSRF hardening.** Third-party article URLs come from attacker-influenced advisory data, so they are fetched only by `SafeFetcher` (`intel/fetcher.py`), the single component allowed outside the host allow-list. Every hop (the first URL and each of at most three redirects) passes, in order: HTTPS-only URL policy (port 443, no userinfo, no IP literals, a host deny-list); DNS resolution refused if *any* returned address is not globally routable (private, loopback, link-local, CGNAT, multicast, ULA, IPv4-mapped/6to4/Teredo embeddings), with the vetted address **pinned** — the TCP connection goes to that IP while SNI, certificate verification and the `Host` header use the real hostname, defeating DNS rebinding; robots.txt (RFC 9309) honoured and cached; per-host politeness delay and a global concurrency cap; streaming reads with a decoded-byte cap, wall-clock limit and content-type allow-list; no cookies, proxies or auth; 403/405/429 recorded, never circumvented.

**Untrusted-content spotlighting.** Fetched HTML is reduced to clean text by a stdlib-only extractor (`intel/extract.py`) that never executes JavaScript and drops *hidden* content — `display:none`, zero-size, off-screen, transparent, `aria-hidden`, screen-reader-only classes, comments — the usual carrier of prompt-injection payloads aimed at an LLM. Before any such text reaches a terminal, document or model it is sanitised (`textsafe`) and wrapped by `untrusted_block()` in nonce-tagged delimiters the content cannot close or forge, with system rules stating that fenced content is data, not instructions.

Optional web search for candidate URLs exists (`intel/search.py`, `STARTUP_SBOM_SEARCH=brave|tavily|searxng` with the user's own key or instance) but is disabled by default, and every hit still goes through `SafeFetcher`.

## The explainable-AI layer

Startup-SBOM is a glass-box system — a closed-form risk formula, published SSVC tables, forward-chaining rules — so `explain/` computes explanations *from the model itself* rather than approximating them post hoc (NIST IR 8312 is the reference frame):

* **Provenance** (`provenance.py`): every conclusion traces to content-addressed `Evidence` facts (`ev:` + SHA-256 of kind|source|locator|statement, so identical facts get identical ids across runs) and `Derivation` records of rule firings whose confidence is the weakest link over their premises. Assumptions are explicit `DEFAULT` evidence, always surfaced.
* **Exact additive explanations** (`attribution.py`): each threat's `risk/1` score is decomposed by a sequential + LMDI scheme into signed per-factor contributions with the invariant `baseline + Σ contributions == total` to machine precision — the `Explanation` model rejects anything inexact. Chain scores (`chain/1`) are decomposed the same way.
* **SSVC traces** (`ssvc_trace.py`): the decision path through the verbatim CERT/CC tables (CISA Coordinator 2.0.3 and the BOD 26-04 remediation-timeline tree), recording every decision point's chosen value, alternatives, rationale, evidence and source, the table row used, and every single-input change that would flip the outcome.
* **Counterfactual fixes** (`counterfactual.py`): breaking every attack chain is a weighted hitting-set problem (NP-hard), so the report carries the greedy approximation, an exact minimum-cost search over small plans, and an Edmonds–Karp min-cut on the privilege-state graph (an upper bound when one fix removes several edges), plus per-fix what-ifs with risk before/after.
* **Global drivers** (`global_.py`): system risk is a noisy-OR over chains and un-chained threats, `S = 100·(1 − Π(1 − sᵢ/100))`, attributed exactly in log-survival space and rolled up to packages, services and vendors with a Pareto view ("N packages explain 80 % of risk").

**Graphs** (`viz/`): the same explanations render as deterministic terminal visuals — waterfalls, bars, trees and diagrams that honour `NO_COLOR`, narrow widths and ASCII-only terminals, never use colour as the only channel, and pass every untrusted string through `textsafe` — and as dependency-free, CSP-safe SVG charts for the HTML and PDF reports (XML-escaped text, no `style=` attributes or scripts, a Sugiyama-lite layered layout for the attack graph).

## The agentic AI layer

`startup-sbom ai analyze report.json` (extra `startup-sbom[ai]`, built on **pydantic-ai**) runs an orchestrator plus specialist agents over a finished report and attaches an `AIAssessment` to it. Agents only *read* the report, through paged, size-capped tools whose every result is wrapped in escaped `<untrusted_scan_data>` delimiters; there are no tools with side effects and no filesystem, network or shell access. A shared cost guard enforces `--max-cost` (default $1.00).

**Providers** (`ai/providers.py`): `anthropic`, `openai`, `google`, `groq`, `mistral` and `openrouter`, each with `cheap` / `balanced` / `quality` profiles mapped to concrete models with per-MTok prices for cost estimation; `startup-sbom ai providers` shows what is configured. Auto-detection and fallback chains pick a configured provider when none is named; `--audience technical|executive` and `--format text|json|markdown|pdf` shape the output.

**Web search** (`ai/websearch.py`): an optional DuckDuckGo tool (pydantic-ai's `duckduckgo_search_tool`) for context lookups — never enabled for offline scans, degrading gracefully when the dependency is missing, with results sanitised and fenced like scan data (`--web-search/--no-web-search`).

**Grounding validation** (`ai/grounding.py`): every output is machine-checked against the report — every cited id must exist, every CVE/GHSA/CWE/ATT&CK id mentioned in any string must be present in the report, every numeric claim (risk score, EPSS, CVSS, likelihood) must match within tolerance, and claims must cite at least one id. Failures raise a retry with precise feedback; on the last attempt the issues are recorded in the assessment's `GroundingResult` instead, and the CLI warns.

**Serving** — the same read-only view of a report can be served to other tools and agents:

* `startup-sbom ai mcp` — a **Model Context Protocol** server (official `mcp` SDK; stdio by default, streamable HTTP binds 127.0.0.1). Read-only by design: the single side-effectful tool, `scan_target`, is registered only when started with explicit `--allow-scan PREFIX` roots.
* `startup-sbom ai serve` — the orchestrator and specialists over **A2A 1.0** (`fasta2a`; agent cards at the root and under `/agents/<name>`) and/or an **ACP** REST facade (ACP = *Agent Communication Protocol*): a dependency-free Starlette implementation of `GET /ping`, `GET /agents`, `GET /agents/{name}`, `POST /runs` (sync/async/stream) and `GET /runs/{id}`, since the archived `acp-sdk` is unusable. Both bind 127.0.0.1 by default; a bearer token (`STARTUP_SBOM_AGENT_TOKEN`) is required on any other interface.

Importing the `ai` package sets `PYDANTIC_AI_NO_BANNER=1` unless you have set it yourself, so pydantic-ai's start-up banner does not tear through the live dashboard or the TUI.

**Registry** (`ai/registry.py`): specialists are discoverable and extensible — built-ins, Python entry-point plugins in the `startup_sbom.agents` group (loaded only when explicitly allow-listed, since loading runs third-party code), and remote A2A/ACP agents by URL (never proxied through the local servers). `startup-sbom ai agents` lists them all.

## Live analyst vs. post-scan assessment

`startup-sbom scan --ai-live` ([Live Scanning](live-scanning.md#the-live-analyst)) and `startup-sbom ai analyze` both use the providers above, but they do different jobs:

| | Live analyst (`--ai-live`) | Post-scan assessment (`ai analyze`) |
|---|---|---|
| When | while the scan runs, once per finished stage | on a finished `report.json` |
| Input | the stage digest, its key numbers and the last 12 raw operations | the whole report, through paged, size-capped read-only tools |
| Tools | none | read-only report tools, optional web search |
| Model | the provider's cheap specialist model, or `--ai-model` | orchestrator plus specialists, by `--profile` or `--model` |
| Spending cap | `--ai-budget`, default USD 0.10 | `--max-cost`, default USD 1.00 |
| Output | display-only commentary in the dashboard / TUI and after the console summary; not stored in the report | an `AIAssessment` attached to the report, grounding-checked |

The live analyst is a reading aid for whoever watches the scan. Its commentary is not grounding-checked and is never written into the report, so nothing downstream — SARIF, VEX, `--fail-on` — depends on it. Use `ai analyze` when you need a stored, checked assessment.
