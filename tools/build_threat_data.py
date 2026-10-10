#!/usr/bin/env python3
"""Build the compact threat-analysis data files shipped in ``src/startup_sbom/data/``.

Development/release tool only (stdlib, network access).  The runtime never
downloads or parses these sources; it reads the derived JSON written here.

Sources (all fetched over HTTPS from their publishers):

* MITRE CWE XML (``cwec_latest.xml.zip``)            -> ``cwe.json``
* MITRE ATT&CK Enterprise STIX bundle                -> ``attack_techniques.json``
* CTID Mappings Explorer KEV -> ATT&CK (Apache-2.0)  -> ``kev_attack.json``
* CTID attack_to_cve CSV (Apache-2.0)                -> merged into ``kev_attack.json``
* MITRE CAPEC XML (CWE -> CAPEC -> ATT&CK join)      -> ``capec_attack.json``

Usage::

    python tools/build_threat_data.py               # download into a temp dir
    python tools/build_threat_data.py --src DIR     # reuse files already in DIR

The XML parsed here is MITRE's own published catalogue (trusted input); the
runtime package never parses XML.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "startup_sbom" / "data"

URLS = {
    "cwec_latest.xml.zip": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "capec_latest.xml": "https://capec.mitre.org/data/xml/capec_latest.xml",
    "enterprise-attack.json": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    ),
    "kev_attack.json": (
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
        "mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/"
        "kev-07.28.2025_attack-16.1-enterprise.json"
    ),
    "attack_to_cve.csv": (
        "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
        "attack_to_cve/master/Att%26ckToCveMappings.csv"
    ),
}

CWE_NS = "{http://cwe.mitre.org/cwe-7}"
CAPEC_NS = "{http://capec.mitre.org/capec-3}"
TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def fetch(src: Path) -> None:
    """Download every source file missing from ``src``."""
    for name, url in URLS.items():
        target = src / name
        if target.exists():
            continue
        print(f"fetching {url}")
        with urllib.request.urlopen(url, timeout=300) as resp:
            target.write_bytes(resp.read())


def _dump(name: str, data: object) -> None:
    path = OUT / name
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size:,} bytes)")


# --------------------------------------------------------------------------- CWE
def build_cwe(src: Path) -> None:
    """``{"impacts": [...], "scopes": [...], "cwe": {id: {n, i, s, p, a?, c?}}}``."""
    with zipfile.ZipFile(src / "cwec_latest.xml.zip") as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        root = ET.fromstring(zf.read(xml_name))  # noqa: S314 - trusted MITRE XML
    impacts: dict[str, int] = {}
    scopes: dict[str, int] = {}
    entries: dict[str, dict[str, object]] = {}

    def idx(table: dict[str, int], value: str) -> int:
        return table.setdefault(value, len(table))

    for w in root.iter(f"{CWE_NS}Weakness"):
        wid = w.get("ID", "")
        imp: set[int] = set()
        scp: set[int] = set()
        for cons in w.iter(f"{CWE_NS}Consequence"):
            for i in cons.iter(f"{CWE_NS}Impact"):
                if i.text:
                    imp.add(idx(impacts, i.text.strip()))
            for s in cons.iter(f"{CWE_NS}Scope"):
                if s.text:
                    scp.add(idx(scopes, s.text.strip()))
        parents = sorted(
            {
                int(r.get("CWE_ID", "0"))
                for r in w.iter(f"{CWE_NS}Related_Weakness")
                if r.get("Nature") == "ChildOf" and r.get("View_ID") == "1000"
            }
        )
        capec = sorted(
            {int(r.get("CAPEC_ID", "0")) for r in w.iter(f"{CWE_NS}Related_Attack_Pattern")}
        )
        entry: dict[str, object] = {"n": w.get("Name", ""), "i": sorted(imp), "s": sorted(scp)}
        if parents:
            entry["p"] = parents
        if capec:
            entry["c"] = capec
        if w.get("Abstraction"):
            entry["a"] = (w.get("Abstraction") or "")[:1]
        entries[wid] = entry

    # Categories carry no consequences: keep the impacts shared by >= half of the
    # member weaknesses (falling back to the single most common impact).
    for c in root.iter(f"{CWE_NS}Category"):
        cid = c.get("ID", "")
        members = [m.get("CWE_ID", "") for m in c.iter(f"{CWE_NS}Has_Member") if m.get("CWE_ID")]
        counts: Counter[int] = Counter()
        scount: Counter[int] = Counter()
        n = 0
        for m in members:
            e = entries.get(m)
            if not e or not e["i"]:
                continue
            n += 1
            counts.update(e["i"])  # type: ignore[arg-type]
            scount.update(e["s"])  # type: ignore[arg-type]
        keep = sorted(k for k, v in counts.items() if n and v * 2 >= n)
        if not keep and counts:
            keep = [counts.most_common(1)[0][0]]
        skeep = sorted(k for k, v in scount.items() if n and v * 2 >= n)
        entries[cid] = {"n": c.get("Name", ""), "i": keep, "s": skeep, "a": "C"}

    _dump(
        "cwe.json",
        {
            "meta": {
                "source": "MITRE CWE",
                "version": root.get("Version"),
                "date": root.get("Date"),
                "url": URLS["cwec_latest.xml.zip"],
            },
            "impacts": [k for k, _ in sorted(impacts.items(), key=lambda kv: kv[1])],
            "scopes": [k for k, _ in sorted(scopes.items(), key=lambda kv: kv[1])],
            "cwe": entries,
        },
    )


# --------------------------------------------------------------------------- ATT&CK
def build_attack(src: Path) -> set[str]:
    """``{"tactics": {short: [name, order]}, "techniques": {id: [name, [tactics]]}}``."""
    bundle = json.loads((src / "enterprise-attack.json").read_text(encoding="utf-8"))
    objects = bundle["objects"]
    version = None
    tactic_names: dict[str, str] = {}
    order: list[str] = []
    for o in objects:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version")
        if o.get("type") == "x-mitre-tactic" and not o.get("revoked"):
            tactic_names[o["x_mitre_shortname"]] = o["name"]
        if o.get("type") == "x-mitre-matrix" and not o.get("revoked"):
            refs = o.get("tactic_refs", [])
            by_id = {t["id"]: t for t in objects if t.get("type") == "x-mitre-tactic"}
            order = [by_id[r]["x_mitre_shortname"] for r in refs if r in by_id]
    techniques: dict[str, list[object]] = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next(
            (
                r["external_id"]
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not tid or not TECH_RE.match(tid):
            continue
        tactics = sorted(
            {
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            },
            key=lambda t: order.index(t) if t in order else 99,
        )
        techniques[tid] = [o["name"], tactics]
    # Sub-techniques get their conventional "Parent: Child" display name.
    for tid, entry in techniques.items():
        parent = techniques.get(tid.split(".")[0]) if "." in tid else None
        if parent is not None:
            entry[0] = f"{parent[0]}: {entry[0]}"
    tactics_out = {
        short: [name, order.index(short) if short in order else 99]
        for short, name in tactic_names.items()
    }
    _dump(
        "attack_techniques.json",
        {
            "meta": {
                "source": "MITRE ATT&CK Enterprise",
                "version": version,
                "url": URLS["enterprise-attack.json"],
            },
            "tactics": tactics_out,
            "techniques": techniques,
        },
    )
    return set(techniques)


# --------------------------------------------------------------------------- CTID
def _split_techs(value: str, known: set[str]) -> list[str]:
    out = []
    for raw in re.split(r"[;,]", value or ""):
        t = raw.strip().upper()
        if t and TECH_RE.match(t) and t in known:
            out.append(t)
    return out


def build_cve_attack(src: Path, known: set[str]) -> None:
    """``{"groups": {...}, "cves": {CVE: {e, p, s, g?, src}}}`` (KEV first, CSV fills gaps)."""
    kev = json.loads((src / "kev_attack.json").read_text(encoding="utf-8"))
    key = {"exploitation_technique": "e", "primary_impact": "p", "secondary_impact": "s"}
    cves: dict[str, dict[str, object]] = {}
    for m in kev["mapping_objects"]:
        cve = (m.get("capability_id") or "").upper()
        k = key.get(m.get("mapping_type") or "")
        tid = (m.get("attack_object_id") or "").upper()
        if not cve.startswith("CVE-") or not k or tid not in known:
            continue
        e = cves.setdefault(cve, {"src": "kev"})
        lst = e.setdefault(k, [])
        if isinstance(lst, list) and tid not in lst:
            lst.append(tid)
        if m.get("capability_group"):
            e["g"] = m["capability_group"]
    text = (src / "attack_to_cve.csv").read_text(encoding="utf-8-sig")
    for row in csv.DictReader(io.StringIO(text)):
        cve = (row.get("CVE ID") or "").strip().upper()
        if not cve.startswith("CVE-") or cve in cves:
            continue
        entry: dict[str, object] = {"src": "ctid"}
        for col, k in (
            ("Exploitation Technique", "e"),
            ("Primary Impact", "p"),
            ("Secondary Impact", "s"),
        ):
            techs = _split_techs(row.get(col) or "", known)
            if techs:
                entry[k] = techs
        if len(entry) > 1:
            cves[cve] = entry
    for e in cves.values():
        for k in ("e", "p", "s"):
            if k in e:
                e[k] = sorted(set(e[k]))  # type: ignore[arg-type]
    meta = kev["metadata"]
    _dump(
        "kev_attack.json",
        {
            "meta": {
                "source": "Center for Threat-Informed Defense (Apache-2.0)",
                "kev_mapping": f"KEV {meta.get('mapping_framework_version')} / "
                f"ATT&CK {meta.get('attack_version')}",
                "urls": [URLS["kev_attack.json"], URLS["attack_to_cve.csv"]],
            },
            "groups": meta.get("capability_groups", {}),
            "cves": cves,
        },
    )


def build_capec(src: Path, known: set[str]) -> None:
    """``{"cwe": {id: [techniques]}}`` from CAPEC's CWE and ATT&CK taxonomy links."""
    root = ET.parse(src / "capec_latest.xml").getroot()  # noqa: S314 - trusted MITRE XML
    by_cwe: dict[str, set[str]] = {}
    for ap in root.iter(f"{CAPEC_NS}Attack_Pattern"):
        if ap.get("Status") in ("Deprecated", "Obsolete"):
            continue
        techs = set()
        for tm in ap.iter(f"{CAPEC_NS}Taxonomy_Mapping"):
            if tm.get("Taxonomy_Name") != "ATTACK":
                continue
            ent = tm.find(f"{CAPEC_NS}Entry_ID")
            if ent is not None and ent.text:
                tid = "T" + ent.text.strip().lstrip("Tt")
                if tid in known:
                    techs.add(tid)
        if not techs:
            continue
        for rw in ap.iter(f"{CAPEC_NS}Related_Weakness"):
            cwe = rw.get("CWE_ID")
            if cwe:
                by_cwe.setdefault(cwe, set()).update(techs)
    _dump(
        "capec_attack.json",
        {
            "meta": {
                "source": "MITRE CAPEC",
                "version": root.get("Version"),
                "date": root.get("Date"),
                "url": URLS["capec_latest.xml"],
            },
            "cwe": {k: sorted(v) for k, v in sorted(by_cwe.items(), key=lambda kv: int(kv[0]))},
        },
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", type=Path, help="directory holding (or receiving) source files")
    args = ap.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        src = args.src or Path(tmp)
        src.mkdir(parents=True, exist_ok=True)
        fetch(src)
        build_cwe(src)
        known = build_attack(src)
        build_cve_attack(src, known)
        build_capec(src, known)
    return 0


if __name__ == "__main__":
    sys.exit(main())
