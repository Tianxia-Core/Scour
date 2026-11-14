#!/usr/bin/env python3
# ffp: TX-SCOUR-EXTRA io-edge python
"""
tx_scour_extra.py -- expanded scour sources feeding Ndimmorwyn signals.

REVISION: TX-SCOUR-EXTRA-002 BASELINE: BASELINE.json

Sources: defillama (stable yields), hn (demand signals), gnews (Google News RSS:
finance/politics/crypto/tech queries), gitee, codeberg, fediverse (Mastodon
trends), nature (RSS), cointelegraph (crypto RSS).

  defillama [--min-apy N] [--min-tvl N] [--chain C]
  hn [--query Q] [--hits N]
  gnews [--query Q] [--topic finance|politics|crypto|tech]
  gitee [--query Q] [--hits N]
  codeberg [--query Q] [--hits N]
  fediverse [--hits N]
  nature [--hits N]
  crypto [--hits N]
  all            run everything -> docs/ndimmorwyn/SIGNALS_EXTRA.json

Exit: 0 ok | 2 environment error.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

OUT = os.environ.get("TX_SIGNALS_EXTRA", "/var/lib/tianxia/docs/ndimmorwyn/SIGNALS_EXTRA.json")
UA = {"User-Agent": "Mozilla/5.0 (compatible; tx-scour-extra/2.0)"}


LOG = logging.getLogger("tx_scour_extra")
if not LOG.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(logging.Formatter("[tx_scour_extra %(asctime)s] %(message)s", datefmt="%H:%M:%S"))
    LOG.addHandler(_handler)
    LOG.setLevel(logging.INFO)


def log(msg: str) -> None:
    """Single stderr sink for this module (house style: the logging module)."""
    LOG.info("%s", msg)


def _get(url: str, timeout: int = 30, binary: bool = False):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return raw if binary else raw.decode("utf-8", "ignore")


def jget(url: str, timeout: int = 30):
    return json.loads(_get(url, timeout))


def rss_items(url: str, hits: int) -> list[dict]:
    try:
        root = ET.fromstring(_get(url, binary=True))
    except (OSError, ET.ParseError) as exc:
        log(f"rss {url} failed: {exc}")
        return []
    out = []
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1] != "item":
            continue
        title = link = desc = ""
        for child in item:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "title":
                title = (child.text or "").strip()
            elif tag == "link":
                link = (child.text or "").strip()
            elif tag == "description":
                desc = re.sub(r"<[^>]+>", "", child.text or "")[:160]
        out.append({"name": title, "url": link, "desc": desc})
        if len(out) >= hits:
            break
    return out


def sig(source: str, name: str, desc: str, **extra) -> dict:
    d = {"source": source, "name": name, "desc": desc, "ts": time.time()}
    d.update(extra)
    return d


def scour_defillama(min_apy: float, min_tvl: float, chain: str | None) -> list[dict]:
    try:
        data = jget("https://yields.llama.fi/pools").get("data", [])
    except (OSError, json.JSONDecodeError) as exc:
        log(f"defillama failed: {exc}")
        return []
    pools = [p for p in data if p.get("stablecoin") and (p.get("apy") or 0) >= min_apy
             and (p.get("tvlUsd") or 0) >= min_tvl]
    if chain:
        pools = [p for p in pools if p.get("chain", "").lower() == chain.lower()]
    pools.sort(key=lambda p: -(p.get("apy") or 0))
    return [sig("defillama", f"{p.get('project')}:{p.get('symbol')}",
                f"stable yield apy={p.get('apy'):.1f}% tvl=${(p.get('tvlUsd') or 0) / 1e6:.0f}M chain={p.get('chain')}",
                chain=p.get("chain"), apy=p.get("apy"), tvlUsd=p.get("tvlUsd"),
                url=f"https://defillama.com/yields/pool/{p.get('pool')}") for p in pools[:25]]


def scour_hn(query: str, hits: int) -> list[dict]:
    try:
        data = jget("https://hn.algolia.com/api/v1/search?query=" + urllib.parse.quote(query)
                    + "&tags=ask_hn&hitsPerPage=" + str(hits))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"hn failed: {exc}")
        return []
    return [sig("hn", h.get("title") or "?", f"ask-hn points={h.get('points')} comments={h.get('num_comments')} q={query!r}",
                url=f"https://news.ycombinator.com/item?id={h.get('objectID')}") for h in data.get("hits", [])]


def scour_hn_official(hits: int) -> list[dict]:
    """Official HN Firebase API (no key, no rate limit): topstories -> items."""
    try:
        ids = jget("https://hacker-news.firebaseio.com/v0/topstories.json")
    except (OSError, json.JSONDecodeError) as exc:
        log(f"hn-official ids failed: {exc}")
        return []
    out = []
    for iid in (ids or [])[:hits * 2]:
        try:
            it = jget(f"https://hacker-news.firebaseio.com/v0/item/{iid}.json")
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(it, dict) or it.get("type") not in ("story", "job"):
            continue
        out.append(sig("hn-official", it.get("title") or "?",
                       f"score={it.get('score', '?')} comments={it.get('descendants', '?')} by={it.get('by', '?')}",
                       url=it.get("url") or f"https://news.ycombinator.com/item?id={iid}",
                       score=it.get("score", 0)))
        if len(out) >= hits:
            break
    return out


GNEWS_TOPICS = {
    "finance": "finance OR markets OR central bank when:7d",
    "politics": "geopolitics OR sanctions OR regulation when:7d",
    "crypto": "crypto OR bitcoin OR stablecoin OR defi when:7d",
    "tech": "AI OR LLM OR developer tools when:7d",
}


def scour_gnews(query: str | None, topic: str | None, hits: int) -> list[dict]:
    q = query or GNEWS_TOPICS.get(topic or "tech", GNEWS_TOPICS["tech"])
    url = ("https://news.google.com/rss/search?q=" + urllib.parse.quote(q)
           + "&hl=en-US&gl=US&ceid=US:en")
    items = rss_items(url, hits)
    return [sig("gnews", i["name"], f"topic={topic or 'custom'} {i['desc']}", url=i["url"]) for i in items]


def scour_gitee(query: str, hits: int) -> list[dict]:
    try:
        data = jget("https://gitee.com/api/v5/search/repositories?q=" + urllib.parse.quote(query)
                    + "&sort=stars_count&order=desc&per_page=" + str(hits))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"gitee failed: {exc}")
        return []
    out = []
    for r in data if isinstance(data, list) else []:
        out.append(sig("gitee", r.get("full_name") or "?",
                       f"stars={r.get('stargazers_count')} {r.get('description') or ''}"[:200],
                       url=r.get("html_url")))
    return out


def scour_codeberg(query: str, hits: int) -> list[dict]:
    try:
        data = jget("https://codeberg.org/api/v1/repos/search?q=" + urllib.parse.quote(query)
                    + "&limit=" + str(hits))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"codeberg failed: {exc}")
        return []
    return [sig("codeberg", r.get("full_name") or "?",
                f"stars={r.get('stars_count')} {r.get('description') or ''}"[:200],
                url=r.get("html_url")) for r in data.get("data", [])]


def scour_fediverse(hits: int) -> list[dict]:
    try:
        tags = jget("https://mastodon.social/api/v1/trends/tags")
    except (OSError, json.JSONDecodeError) as exc:
        log(f"fediverse failed: {exc}")
        return []
    return [sig("fediverse", "#" + t.get("name", "?"),
                f"uses7d={t.get('history', [{}])[0].get('uses', '?')} trending on mastodon",
                url=f"https://mastodon.social/tags/{t.get('name')}") for t in tags[:hits]]


def scour_nature(hits: int) -> list[dict]:
    return [sig("nature", i["name"], i["desc"], url=i["url"])
            for i in rss_items("https://www.nature.com/nature.rss", hits)]


def scour_crypto(hits: int) -> list[dict]:
    return [sig("cointelegraph", i["name"], i["desc"], url=i["url"])
            for i in rss_items("https://cointelegraph.com/rss", hits)]


def scour_vast(hits: int) -> list[dict]:
    items = scour_gnews("vast.ai OR GPU rental rates OR cloud GPU pricing", None, hits)
    for it in items:
        it["source"] = "vast"
        it["kind"] = "gpu-compute"
    return items


def scour_fragment(hits: int) -> list[dict]:
    items = scour_gnews("Telegram channel ads OR Telegram bot monetization OR TON Fragment", None, hits)
    for it in items:
        it["source"] = "fragment"
        it["kind"] = "handle-auction"
    return items


def scour_merchant(hits: int) -> list[dict]:
    items = scour_gnews(
        "high-risk merchant underwriting OR Stripe chargeback fee OR merchant payments compliance",
        None, hits)
    for it in items:
        it["source"] = "merchant"
        it["kind"] = "merchant-underwriting"
    return items


def scour_quota(hits: int) -> list[dict]:
    items = scour_gnews("LLM API pricing OR AI token pricing OR AI credit discount", None, hits)
    for it in items:
        it["source"] = "quota"
        it["kind"] = "token-quota"
    return items


def scour_livelihood(hits: int) -> list[dict]:
    items = scour_gnews("Principal AI Architect remote hiring OR Lead Systems Architect salary", None, hits)
    for it in items:
        it["source"] = "livelihood"
        it["kind"] = "fte-placement"
    return items


def scour_recovery(hits: int) -> list[dict]:
    items = scour_gnews("dormant crypto wallet recovery OR unclaimed airdrop claim", None, hits)
    for it in items:
        it["source"] = "recovery"
        it["kind"] = "ghost-recovery"
    return items


def scour_triad(hits: int) -> list[dict]:
    items = scour_gnews("crypto arbitrage OR DEX arbitrage OR triangular arbitrage", None, hits)
    for it in items:
        it["source"] = "triad"
        it["kind"] = "triad-arb"
    return items


def scour_asura(hits: int) -> list[dict]:
    items = scour_gnews(
        "asymmetric strategy OR game theory OR alternative capital",
        None, hits)
    for it in items:
        it["source"] = "asura"
        it["kind"] = "asura-matrix"
    return items


def scour_x402(hits: int) -> list[dict]:
    items = scour_gnews(
        "HTTP 402 Payment Required AI agent OR agent.market API micropayment OR agentic per-call pricing",
        None, hits)
    for it in items:
        it["source"] = "x402"
        it["kind"] = "signal-api"
    return items


def scour_digest(hits: int) -> list[dict]:
    items = scour_gnews(
        "developer intelligence newsletter OR weekly AI architecture roundup OR sovereign tech digest",
        None, hits)
    for it in items:
        it["source"] = "digest"
        it["kind"] = "newsletter-digest"
    return items


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["defillama", "hn", "gnews", "gitee", "codeberg",
                                     "fediverse", "nature", "crypto", "hn_official",
                                     "vast", "fragment", "merchant", "quota",
                                     "livelihood", "recovery", "triad", "asura",
                                     "x402", "digest", "all"])
    ap.add_argument("--min-apy", type=float, default=8.0)
    ap.add_argument("--min-tvl", type=float, default=5e6)
    ap.add_argument("--chain", default=None)
    ap.add_argument("--query", default="I would pay for")
    ap.add_argument("--topic", default=None, choices=["finance", "politics", "crypto", "tech"])
    ap.add_argument("--hits", type=int, default=15)
    args = ap.parse_args()

    signals: list[dict] = []
    runners = {
        "defillama": lambda: scour_defillama(args.min_apy, args.min_tvl, args.chain),
        "hn": lambda: scour_hn(args.query, args.hits),
        "gnews": lambda: scour_gnews(None, args.topic, args.hits),
        "gitee": lambda: scour_gitee(args.query if args.query != "I would pay for" else "ai agent", args.hits),
        "codeberg": lambda: scour_codeberg("ai" if args.query == "I would pay for" else args.query, args.hits),
        "fediverse": lambda: scour_fediverse(args.hits),
        "nature": lambda: scour_nature(args.hits),
        "crypto": lambda: scour_crypto(args.hits),
        "hn_official": lambda: scour_hn_official(args.hits),
        "vast": lambda: scour_vast(args.hits),
        "fragment": lambda: scour_fragment(args.hits),
        "merchant": lambda: scour_merchant(args.hits),
        "quota": lambda: scour_quota(args.hits),
        "livelihood": lambda: scour_livelihood(args.hits),
        "recovery": lambda: scour_recovery(args.hits),
        "triad": lambda: scour_triad(args.hits),
        "asura": lambda: scour_asura(args.hits),
        "x402": lambda: scour_x402(args.hits),
        "digest": lambda: scour_digest(args.hits),
    }
    if args.mode == "all":
        for name, fn in runners.items():
            got = fn()
            signals += got
            log(f"{name}: {len(got)} signals")
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w") as fh:
            json.dump({"updated": time.time(), "count": len(signals), "signals": signals}, fh, indent=1)
        log(f"wrote {len(signals)} signals -> {OUT}")
    else:
        signals = runners[args.mode]()
    for s in signals[:10]:
        print(json.dumps(s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
