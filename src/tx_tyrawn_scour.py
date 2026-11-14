#!/usr/bin/env python3
# ffp: TX-TYRAWN-SCOUR io-edge python
"""tx_tyrawn_scour.py -- Tyrawn scouring upgrades (revgen-fed signals).

Modes (verified live 2026-09-27):
  funding    -- funding-announcement tracking: TechCrunch RSS + Google News
                RSS funding query, filtered to raise/series/seed headlines.
  jobchange  -- job-change/expansion signals from the RemoteOK public API
                (already the backbone of tx_jobmatch; here emitted as signals).
  techstack  -- HONEST SKIP: no free verified API (BuiltWith is paid; Wappalyzer
                has no public free tier). Records the gap instead of guessing.

Normalized records match the MERGED_SIGNALS schema and are appended append-only
to the merged signals file. Kill-switch honored; urllib only (no shell).
REVISION: TX-TYRAWN-SCOUR-001 BASELINE: BASELINE.session.json
Usage: tx_tyrawn_scour.py funding|jobchange|techstack [--hits N] [--out FILE] [--dry]
Env: TX_BASE_DIR, TX_TYRAWN_SCOUR_HITS, TX_SIGNALS_FILE, TX_TYRAWN_SCOUR_URL."""
import argparse
import json
import logging
import os
import sys
import time
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

log = logging.getLogger("tx_tyrawn_scour")
BASE = Path(os.environ.get("TX_BASE_DIR", str(Path(__file__).resolve().parents[1])))
OUT = Path(os.environ.get("TX_SIGNALS_FILE", str(BASE / "docs" / "ndimmorwyn" / "MERGED_SIGNALS.jsonl")))
HITS = int(os.environ.get("TX_TYRAWN_SCOUR_HITS", "12"))
UA = {"User-Agent": "Tianxia-Tyrawn/1.0"}
FUND_FEEDS = ("https://techcrunch.com/feed/",
              "https://news.google.com/rss/search?q=startup+raises+funding+round&hl=en-US&gl=US&ceid=US:en")
FUND_WORDS = ("raises", "raised", "funding", "series a", "series b", "series c",
              "seed round", "seed funding", "secures", "investment", "led by", "valuation")


def _halt() -> bool:
    return bool(os.environ.get("AUTONOMY_PAUSED") or os.environ.get("PROBE_STOP"))


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read()


def _strip(html: str) -> str:
    out, depth = [], 0
    for ch in html or "":
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return " ".join("".join(out).split())


def _rss(url: str, hits: int) -> list:
    try:
        root = ET.fromstring(_get(url))
    except (OSError, ValueError, ET.ParseError) as exc:
        log.warning("rss %s failed: %s", url, exc)
        return []
    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        desc = _strip(item.findtext("description") or "")[:400]
        if title:
            out.append({"title": title, "url": link, "text": desc})
        if len(out) >= hits:
            break
    return out


def _sig(mode: str, title: str, text: str, url: str, kind: str = "signal") -> dict:
    return {"source": "tyrawn_scour", "subsource": mode, "kind": kind, "title": str(title)[:200],
            "text": str(text)[:500], "url": url, "metrics": {}, "score": None, "ts": time.time()}


def funding(hits: int) -> list:
    recs = []
    for feed in FUND_FEEDS:
        for it in _rss(feed, hits):
            if any(w in it["title"].lower() for w in FUND_WORDS):
                recs.append(_sig("funding", it["title"], it["text"], it["url"], "funding"))
    return recs[:hits]


def jobchange(hits: int) -> list:
    try:
        jobs = json.loads(_get("https://remoteok.com/api"))
    except (OSError, ValueError) as exc:
        log.warning("remoteok api failed: %s", exc)
        return []
    seen, recs = set(), []
    for j in jobs if isinstance(jobs, list) else []:
        if not isinstance(j, dict):
            continue
        company = str(j.get("company") or "").strip()
        position = str(j.get("position") or "").strip()
        if not company or company in seen:
            continue
        seen.add(company)
        recs.append(_sig("jobchange", f"{company} hiring {position}", str(j.get("tags", ""))[:300],
                         str(j.get("url") or ""), "jobchange"))
        if len(recs) >= hits:
            break
    return recs


def techstack(hits: int) -> list:
    log.info("techstack: SKIP -- no free verified API (BuiltWith paid; Wappalyzer no free tier)")
    return []


def _append(recs: list) -> int:
    if not recs:
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("a", encoding="utf-8") as fh:
        for rec in recs:
            fh.write(json.dumps(rec) + "\n")
    return len(recs)


def main(argv: list | None = None) -> int:
    global OUT
    global OUT
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Tyrawn scouring upgrades")
    ap.add_argument("mode", nargs="?", choices=("funding", "jobchange", "techstack"), default="funding")
    ap.add_argument("--hits", type=int, default=HITS)
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--dry", action="store_true", help="print only, do not append")
    args = ap.parse_args(argv)
    if _halt():
        log.error("kill-switch engaged; refusing to scour")
        return 1
    OUT = Path(args.out)
    recs = {"funding": funding, "jobchange": jobchange, "techstack": techstack}[args.mode](args.hits)
    appended = 0 if args.dry else _append(recs)
    print(json.dumps({"mode": args.mode, "fetched": len(recs), "appended": appended,
                      "out": str(OUT), "dry": args.dry,
                      "sample": recs[:2]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
