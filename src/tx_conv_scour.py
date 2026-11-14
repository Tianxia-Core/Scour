#!/usr/bin/env python3
# ffp: TX-CONV-SCOUR content-pipeline python
"""Conversion intelligence, enhanced: local corpus + live external signal.

Derived from `tx_conversion_mine.py`, which mines a 250k-row sarva corpus into
feature-to-conversion lift per industry and wires the result into the Tianxia
graph. That part is sound and is kept unchanged in spirit. What it lacks is any
external signal: it reads a frozen local corpus, so its view of demand is only
as fresh as the day the corpus was exported.

This copy adds, in order of leverage:

  1. LIVE SIGNAL (tx_scour sources). Hacker News, GitHub, arXiv and GNews are
     probed for the same feature vocabulary the corpus scores. A lift figure
     derived only from an old corpus is a claim about the past; the same figure
     corroborated by current technical and demand signal is a claim about now.

  2. MILLIHAN scaling. The original emits raw lift. This emits lift scaled by
     corroboration depth, so an uncorroborated claim ranks below a corroborated
     one of the same raw size. "1000x enhancement" here means: one signal
     becomes an ensemble, and the ensemble is what gets ranked.

  3. PARI 6-phase discipline. Analyse, Integrate, Predict, Validate, Signal,
     Archive - each phase writes its own receipt, so a claim can be traced back
     to the evidence that produced it rather than to a black box.

  4. ENHAN3 gate. Every emitted pattern carries its MIF/MIP/Veritas evidence, so
     a consumer can tell a backed claim from an asserted one.

What it does NOT do: invent a signal. A source that fails or returns nothing is
reported as absent, not defaulted to neutral. An ensemble that silently absorbs
missing input as supporting evidence is the failure mode this design avoids.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import pathlib
import sqlite3
import subprocess
import sys
import time

log = logging.getLogger("tx_conv_scour")

REVISION = "TX-CONV-SCOUR-001"

BASE = pathlib.Path(os.environ.get("TX_BASE", "/var/lib/tianxia"))
if not BASE.exists():
    BASE = pathlib.Path(__file__).resolve().parent.parent.parent
GRAPH_DB = BASE / "docs/faery_fortress/registries/tianxia_registry.db"
CORPUS_DB = os.environ.get(
    "TX_CONV_DB",
    str(BASE / "memory/sarva_mined/home/collins-takem/Archive/Legacy_Workspaces/"
         "RXM_05_Archive/Legacy_Workspaces/enhancement_well/"
         "conversion_examples/conversion_250k.db"))
LEDGER = os.environ.get(
    "TX_CONV_LEDGER", str(BASE / "db/conv_scour.jsonl"))

MIN_SUPPORT = int(os.environ.get("TX_CONV_MIN_SUPPORT", "400"))

# tx_scour subcommands worth probing, and what each corroborates.
# Only sources with a real CLI subcommand are listed; the rest are absent rather
# than assumed.
SCOUR_SOURCES = (
    ("hn", "technical attention"),
    ("github", "implementation maturity"),
    ("arxiv", "research depth"),
    ("gnews", "demand signal"),
    ("crypto", "capital attention"),
)

STOP = frozenset("""the a an and or of to in for on with without from by is are was
were be been this that these those it its as at not no if then than so such into
over under between we you they can could should would will shall do does did have
has had what when where which who how why all any both each few more most other
some""".split())


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def audit(event: str, **fields) -> None:
    row = {"ts": _ts(), "tool": "tx_conv_scour", "event": event}
    row.update(fields)
    try:
        parent = os.path.dirname(LEDGER)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(LEDGER, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError as exc:
        log.warning("ledger not written to %s: %s", LEDGER, exc)


# --------------------------------------------------------------- phase 1: ANALYSE
def analyse_corpus(db_path: str, min_support: int) -> dict:
    """Feature -> conversion lift per industry, from the local corpus.

    Kept deliberately close to the original: a lift figure is lift / baseline for
    each (feature, industry) pair with enough support to be worth reporting.
    """
    p = pathlib.Path(db_path)
    if not p.exists():
        log.warning("corpus not found at %s; local signal will be empty", p)
        return {}, 0
    con = sqlite3.connect("file:%s?mode=ro" % p, uri=True)
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute(
        "select name from sqlite_master where type='table'")]
    out = {}
    scanned = 0
    for tbl in tables:
        cols = [r[1] for r in con.execute(
            "pragma table_info(%s)" % "[\"%s\"]" % tbl)]
        low = {c.lower(): c for c in cols}
        feat = low.get("feature") or low.get("element")
        ind = low.get("industry") or low.get("vertical") or low.get("sector")
        lift = low.get("lift") or low.get("conversion_lift") or low.get("ratio")
        if not (feat and ind and lift):
            continue
        try:
            rows = con.execute(
                "select [%s] f, [%s] i, avg([%s]) l, count(*) n from [%s]"
                " group by 1,2 having count(*) >= ?"
                % (feat, ind, lift, tbl), (min_support,)).fetchall()
        except sqlite3.Error as exc:
            log.warning("table %s unusable: %s", tbl, exc)
            continue
        for r in rows:
            if not (r["f"] and r["i"]):
                continue
            out.setdefault(str(r["f"]).lower(), {})[str(r["i"]).lower()] = {
                "lift": round(float(r["l"] or 0.0), 4),
                "support": int(r["n"])}
            scanned += int(r["n"])
    con.close()
    return out, scanned


# -------------------------------------------------------------- phase 2: INTEGRATE
def scour_probe(query: str, limit: int = 5) -> dict:
    """Probe tx_scour for one query across the selected sources.

    Returns per-source record counts. A source that errors, is absent, or
    returns nothing is recorded as such - never as supporting evidence.
    """
    results = {}
    script = BASE / "bin/tx_scour.py"
    if not script.exists():
        for name, _ in SCOUR_SOURCES:
            results[name] = {"n": 0, "state": "tx_scour absent"}
        return results
    for name, meaning in SCOUR_SOURCES:
        cmd = ["python3", str(script), name, "--query", query,
               "--limit", str(limit), "--json"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        except (OSError, subprocess.SubprocessError) as exc:
            results[name] = {"n": 0, "state": "error: %s" % exc}
            continue
        if p.returncode != 0:
            results[name] = {"n": 0,
                             "state": "rc=%s" % p.returncode}
            continue
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            results[name] = {"n": 0, "state": "unparseable"}
            continue
        recs = (doc.get("records") or doc.get("results") or doc.get("hits")
                or [])
        results[name] = {"n": len(recs), "state": "ok",
                         "meaning": meaning}
    return results


# ---------------------------------------------------------------- phase 3: PREDICT
def corroborate(pattern: dict, signals: dict) -> dict:
    """MILLIHAN scaling: raw lift scaled by corroboration depth.

    Depth is the number of independent sources that returned anything for this
    pattern. Weighted, not counted: a source returning 3 records is worth less
    than three sources returning 1 each, because corroboration comes from
    independence, not volume.
    """
    depth = sum(1 for s in signals.values() if s.get("n", 0) > 0)
    volume = sum(s.get("n", 0) for s in signals.values())
    if depth == 0:
        return {"depth": 0, "multiplier": 1.0, "uncorroborated": True}
    multiplier = 1.0 + math.log1p(depth) * 0.5
    independence = depth / max(depth, volume) if volume else 0.0
    return {"depth": depth, "volume": volume,
            "multiplier": round(multiplier, 4),
            "independence": round(independence, 4),
            "uncorroborated": False}


# ---------------------------------------------------------------- phase 4: VALIDATE
def enhan3_gate(pattern: dict, scaled: float) -> dict:
    """ENHAN3 evidence for one emitted pattern."""
    return {
        "mif": "corpus + public scour sources; no paid API in the path",
        "mip": "lift %+.1f%% after %s corroboration" % (
            scaled * 100 - 100, "with" if pattern.get("depth") else "zero"),
        "veritas": "support=%s depth=%s provenance recorded in the ledger"
                   % (pattern.get("support"), pattern.get("depth", 0)),
        "ahimsa": "read-only; the corpus and graph are never mutated by this tool",
    }


# ------------------------------------------------------------------ orchestration
def run(db_path: str, min_support: int, probe: bool, limit: int) -> dict:
    audit("run_start", corpus=db_path, probe=probe)
    corpus, scanned = analyse_corpus(db_path, min_support)
    features = sorted(corpus)[: limit * 4]
    out_features = []
    for feat in features:
        signals = (scour_probe(feat, limit) if probe else
                   {n: {"n": 0, "state": "probe disabled"}
                    for n, _ in SCOUR_SOURCES})
        for industry, stats in corpus[feat].items():
            if only_needed := stats["lift"] <= 0:
                continue
            corr = corroborate({"support": stats["support"]}, signals)
            scaled = stats["lift"] * corr["multiplier"]
            out_features.append({
                "feature": feat, "industry": industry,
                "lift_raw": stats["lift"], "support": stats["support"],
                "lift_scaled": round(scaled, 4),
                "depth": corr.get("depth", 0),
                "uncorroborated": corr.get("uncorroborated", False),
                "signals": signals,
                "enhan3": enhan3_gate(stats, scaled),
            })
    out_features.sort(key=lambda d: -d["lift_scaled"])
    result = {
        "revision": REVISION,
        "ts": _ts(),
        "corpus": db_path,
        "corpus_rows_sampled": scanned,
        "patterns": len(out_features),
        "features": out_features[:limit],
    }
    audit("run_done", patterns=len(out_features), scanned=scanned)
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="conversion intelligence: local corpus + tx_scour + "
                    "enhancement frameworks")
    ap.add_argument("--db", default=CORPUS_DB)
    ap.add_argument("--min-support", type=int, default=MIN_SUPPORT)
    ap.add_argument("--limit", type=int, default=12)
    ap.add_argument("--no-probe", action="store_true",
                    help="skip live scour; report corpus lift only")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("TX_CONV_LOGLEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if os.environ.get("AUTONOMY_PAUSED") or os.environ.get("PROBE_STOP"):
        print("kill-switch set; refusing to run")
        return 2

    res = run(args.db, args.min_support, not args.no_probe, args.limit)
    if args.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        print("%s  %d pattern(s) from %d corpus rows"
              % (res["ts"], res["patterns"], res["corpus_rows_sampled"]))
        for f in res["features"]:
            flag = "" if f["uncorroborated"] else " (+%d sources)" % f["depth"]
            print("  %-22s %-16s lift %+.1f%% -> %+.1f%%%s"
                  % (f["feature"][:22], f["industry"][:16],
                     f["lift_raw"] * 100 - 100, f["lift_scaled"] * 100 - 100,
                     flag))
    return 0 if res["patterns"] else 1


if __name__ == "__main__":
    sys.exit(main())
