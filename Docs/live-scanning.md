# Live Scanning

A scan of a full root filesystem takes from seconds to minutes, most of it spent reading package databases, resolving ELF link closures and querying vulnerability sources. Startup-SBOM shows that work as it happens: a **live dashboard** with a stage checklist, a one-line digest of what each finished stage found, and a rolling pane of raw operations; a **journal** that records the same events as JSON lines; and an optional **live analyst**, a cheap LLM that comments on each stage while the scan runs. None of this changes the report. The code lives in `src/startup_sbom/dashboard.py`, `digest.py`, `log.py` and `ai/live.py`.

## Activity events

The pipeline ([Architecture](architecture.md#the-pipeline)) emits two event streams to whoever listens:

* `ProgressEvent(stage, index, total)` when a stage starts;
* `ActivityEvent(stage, kind, message, data)` while it runs, with `kind` one of:
    * `op` — one **raw operation** from the `startup_sbom.ops` logger;
    * `digest` — what the stage that just finished found: a sentence in `message` and its key numbers in `data`;
    * `stage-failed` — the stage raised and was isolated; the scan continues with partial results.

**Digests** (`digest.py`) summarise the in-memory results of a stage, never the target directly, and bound every free-text value so a hostile image cannot flood a display or a model prompt. Examples: `1,115 OS packages from dpkg`; `214 services (systemd 180, cron 21, udev 13); 96 start automatically (boot 71, timer 14, socket 6, device 5); 41 of them as root`; `412 threats; reachability …; 230 have no trigger (installed code nothing runs); 9 lead to root`.

**Raw operations** are the concrete things a stage does, one line each:

| Source | Example line |
|---|---|
| HTTP requests (`net.py`) | `POST api.osv.dev/v1/querybatch → 200 (412 ms, 38.2 kB)`, or `… failed: ConnectTimeout` |
| Cache hits | `cache hit www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (age 3.1h)` |
| Package databases | `dpkg: 1,115 installed package(s) read` |
| Init systems | `systemd: 180 service(s) configured, 71 automatic`, `PID 1: systemd (…)` |
| ELF closures | `elf /usr/bin/sudo: 9 libraries [setuid]` |
| Language packages | `python: 37 package(s) found` |
| Sandboxed commands ([Chroot Mode](chroot-mode.md)) | `sandbox: /usr/bin/systemctl --root=/ list-unit-files … → exit 0 (210 ms, 9,842 bytes)` |

HTTP operations log the host and path only, never the query string or headers. Without a live display the `ops` logger behaves like any other `startup_sbom` logger, so its lines appear with `--verbose`.

## The CLI dashboard

`startup-sbom scan` draws the dashboard on **stderr** by default when stderr is a terminal. `--live` forces it (as plain timestamped lines when stderr is not a terminal); `--no-live` and `--quiet` always turn it off, even with `--journal` or `--ai-live` (the journal is still written and the analyst's notes are still printed after the summary unless `--quiet`). Report output on stdout (including `-o -`) is never touched. The dashboard shows:

* a header with the target, the number of finished stages and the elapsed time, above a progress bar;
* the **stage checklist**: one row per stage with its duration and, once finished, its digest (a running stage shows how many operations it has performed so far; a failed one shows the error);
* the **raw operations** pane: the last 14 operation lines with timestamps, and the total count;
* the **live analyst** pane, when `--ai-live` is on.

When stderr is not a terminal (CI logs, redirection), the same information is printed as plain timestamped lines: `[3/11] Discovering services`, then `digest: …`, `stage-failed: …` and `analyst: …` lines. Passing `--journal` or `--ai-live` always runs the scan behind the dashboard, in whichever of the two forms fits stderr.

Every string shown comes from the scanned system (or from a model) and is untrusted: it goes through `textsafe.safe()` and is rendered as plain `rich` text, never parsed as markup.

## The journal

`--journal FILE` writes every event as one JSON object per line, for later review or for feeding other tools:

| Field | Meaning |
|---|---|
| `t` | seconds since the scan started (3 decimals) |
| `kind` | `stage`, `op`, `digest`, `stage-failed`, `analyst-info`, `analyst-done` or `analyst-error` |
| `stage` | the stage title (empty for analyst start-up) |
| `message` | for `stage`, the position (`2/11`); otherwise the operation, digest, error or analyst commentary |
| `data` | the digest's key numbers (only present when there are any) |

```json
{"t": 0.412, "kind": "op", "stage": "Reading package databases", "message": "dpkg: 1,115 installed package(s) read"}
{"t": 0.415, "kind": "digest", "stage": "Reading package databases", "message": "1,115 OS packages from dpkg", "data": {"packages": 1115, "databases": ["dpkg"], "by_type": {"deb": 1115}}}
```

The journal is created owner-only (0600, like the reports) and every message is sanitised (control, bidi and invisible characters removed) before it is written. It still describes the scanned system in the same detail as the report — file paths, services, vulnerabilities — so keep it private.

## The live analyst

`--ai-live` lets a cheap model comment on each stage as it finishes: what stands out, how it connects to earlier stages, and what to watch for next. Its thinking (when the provider exposes it) and its commentary stream into the analyst pane; when the scan ends, the commentary of every stage is printed after the console summary under *Live analyst notes (model commentary, not part of the report)*.

```bash
export ANTHROPIC_API_KEY=…          # or any provider key listed by `startup-sbom ai providers`
startup-sbom scan dir:/mnt/target_root --ai-live -f html -o out/
startup-sbom scan dir:/mnt/target_root --ai-live --ai-provider openai --ai-budget 0.05
startup-sbom scan dir:/mnt/target_root --ai-live --ai-model anthropic:<model-id>
```

**Setup.** It needs the `ai` extra (`startup-sbom[ai]`) and a provider key in the environment. The provider is auto-detected unless `--ai-provider` names one; the model is the provider's cheap-profile specialist model unless `--ai-model provider:model-id` names one ([Intelligence and AI](intelligence-and-ai.md#the-agentic-ai-layer) lists the providers). `--ai-live` cannot be combined with `--offline`.

**Cost.** `--ai-budget` (default **USD 0.10**) caps the estimated spend across the whole scan, through the same cost guard as `startup-sbom ai analyze`. Further limits are fixed: 40 model requests and 200,000 tokens per scan and a 45-second timeout per stage. Thinking follows the profile, and no per-stage output cap is imposed, so a provider's thinking budget always fits inside the request's token limit. When the budget is reached the analyst stops, says so in its pane, and the scan carries on.

**Safety.**

* The analyst has **no tools**: it cannot read files, query the report, search the web or take any action. It only produces text.
* Each prompt carries the stage title, the stage digest, the digest's key numbers and the last 12 raw operations, cleaned and size-capped, inside the escaped `<untrusted_scan_data>` delimiters used by the agentic layer. Its instructions say that this is data from the scanned system, never instructions, and that it must not state facts absent from the digests.
* It is **display-only**. Its commentary is not written into the report, and the report's conclusions stay deterministic. The only trace it can leave is a warning `live analyst stopped: <reason>` when it fails.
* It runs on a background thread, one stage at a time, so the scan never waits for the model. When it falls behind, the stages queued meanwhile are folded into one prompt instead of piling up. At the end of the scan it gets up to 60 seconds to finish the queued stages.
* A provider or network error stops the analyst, not the scan.

What leaves the machine is described in [SECURITY.md](https://github.com/morpheuslord/Startup-SBOM/blob/main/SECURITY.md): stage digests and recent operation lines, never file contents or the full report.

The live analyst is separate from the post-scan assessment (`startup-sbom ai analyze`), which reads a finished report through guarded tools and whose claims are grounding-checked; see [Intelligence and AI](intelligence-and-ai.md).

## In the TUI

The [TUI](introduction.md#quick-tour-of-the-cli) scan screen shows the same streams: a live stage list with each stage's digest, a raw operations log, and a live analyst panel. The analyst is switched on in the scan settings (*Live analyst (LLM comments on each stage)*), next to the post-scan AI analysis, and shares its provider, model and spending-cap fields; like `--ai-live`, it is unavailable in offline mode.
