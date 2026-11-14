#!/usr/bin/env python3
# ffp: TX-THREATINTEL io-edge python
"""tx_threatintel.py -- live threat-intel ingestion for the Faery Fortress.

Fetches public no-auth feeds (CISA KEV, NVD 2.0, URLhaus, ThreatFox) and maps
them to MERGED_SIGNALS {source,subsource,kind,title,text,url,metrics,score,ts},
emitting JSONL (paper default). --apply appends THREAT_SIGNALS.jsonl and writes
THREAT_HANDOFF.json for darkmon/malware-lab behind the kill-switch gate. Auth-
walled feeds (OTX, CISA AIS) excluded; all four feeds verified live 200.
REVISION TX-THREATINTEL-001 | Env TX_BASE_DIR, TX_THREAT_SIGNALS/HANDOFF, TX_THREAT_TIMEOUT_S/HITS | AUTONOMY_PAUSED/PROBE_STOP | list-args only.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

REVISION = "TX-THREATINTEL-001"
BASELINE = os.environ.get("TX_BASELINE", "BASELINE.json")
log = logging.getLogger("tx_threatintel")
BASE = Path(os.environ.get("TX_BASE_DIR", "/var/lib/tianxia"))
SIGNALS = Path(os.environ.get("TX_THREAT_SIGNALS", str(BASE / "docs/ndimmorwyn/THREAT_SIGNALS.jsonl")))
HANDOFF = Path(os.environ.get("TX_THREAT_HANDOFF", str(BASE / "docs/ndimmorwyn/THREAT_HANDOFF.json")))
SINKHOLE_HOSTS = Path(os.environ.get("TX_SINKHOLE_HOSTS", str(BASE / "config/sinkhole_hosts.txt")))
SINKHOLE_JSON = Path(os.environ.get("TX_SINKHOLE_JSON", str(BASE / "docs/ndimmorwyn/THREAT_SINKHOLE.json")))
TIMEOUT_S = int(os.environ.get("TX_THREAT_TIMEOUT_S", "15"))
UA = "tx-threatintel/1.0 (+https://hub.local)"
FEEDS = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=40",
    "feodotracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/json_recent/",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
}


def kill_switch() -> bool:
    return bool(os.environ.get("AUTONOMY_PAUSED") or os.environ.get("PROBE_STOP"))


def _get(url: str):
    try:
        headers = {"User-Agent": UA}
        api_key = os.environ.get("ABUSE_CH_API_KEY")
        if api_key and "abuse.ch" in url:
            headers["Auth-Key"] = api_key
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("fetch failed %s: %s", url, exc)
        return None


def _sig(source, subsource, kind, title, text, url, metrics, score):
    return {"source": source, "subsource": subsource, "kind": kind, "title": str(title)[:200],
            "text": str(text)[:500], "url": url, "metrics": metrics,
            "score": round(float(score), 4), "ts": time.time()}


def parse_kev(data, hits):
    def r(v):
        ransom = v.get("knownRansomwareCampaignUse") == "Known"
        cve = str(v.get("cveID"))
        return _sig("cisa-kev", "kev", "exploited-vuln",
                    "%s %s %s" % (cve, v.get("vendorProject"), v.get("product")),
                    v.get("shortDescription"), "https://nvd.nist.gov/vuln/detail/" + cve,
                    {"cve": cve, "ransomware": ransom, "due": v.get("dueDate")},
                    0.95 if ransom else 0.90)
    return [r(v) for v in (data or {}).get("vulnerabilities", [])[:hits]]


def parse_nvd(data, hits):
    def r(item):
        cve = item.get("cve", {}) or {}
        cid, dl = str(cve.get("id")), cve.get("descriptions", []) or []
        desc = next((d.get("value", "") for d in dl if d.get("lang") == "en"), "")
        cv = ((cve.get("metrics", {}) or {}).get("cvssMetricV31") or [{}])[0].get("cvssData", {}) or {}
        return _sig("nvd", "recent", "cve", cid, desc, "https://nvd.nist.gov/vuln/detail/" + cid,
                    {"cvss": cv.get("baseScore"), "severity": cv.get("baseSeverity")},
                    float(cv.get("baseScore", 0.0) or 0.0) / 10.0)
    return [r(i) for i in (data or {}).get("vulnerabilities", [])[:hits]]


def _items(data):
    vals = list(data.values()) if isinstance(data, dict) else list(data or [])
    return [e for v in vals for e in (v if isinstance(v, list) else [v])]


def parse_urlhaus(data, hits):
    def r(u):
        tags = u.get("tags") or []
        return _sig("urlhaus", "recent", "malware-url",
                    "%s %s" % (u.get("threat", "malware"), u.get("host", "")), u.get("url"),
                    u.get("url"), {"status": u.get("url_status"), "tags": tags},
                    0.75 if ("elf" in tags or "exe" in tags) else 0.70)
    return [r(u) for u in _items(data)[:hits]]


def parse_threatfox(data, hits):
    out = []
    for e in _items(data)[:hits]:
        conf = float(e.get("confidence_level", 0) or 0) / 100.0
        out.append(_sig("threatfox", "recent", "ioc",
                        "%s %s" % (e.get("malware_printable") or e.get("malware", "ioc"), e.get("ioc_type", "")),
                        e.get("ioc_value"), "https://threatfox.abuse.ch/",
                        {"ioc_type": e.get("ioc_type"), "first_seen": e.get("first_seen_utc")},
                        max(0.5, min(0.9, conf))))
    return out


def parse_feodo(data, hits):
    def r(item):
        ip = str(item.get("ip_address"))
        port = item.get("port")
        asn = item.get("as_name", "")
        country = item.get("country", "")
        return _sig("feodotracker", "botnet-c2", "c2-ip",
                    f"Botnet C2 {ip}:{port} ({asn}, {country})",
                    f"Active C2 server {ip}:{port} in {country} ({asn})",
                    f"https://feodotracker.abuse.ch/browse/host/{ip}/",
                    {"ip": ip, "port": port, "asn": asn, "country": country},
                    0.88)
    return [r(item) for item in (data or [])[:hits]]


PARSERS = {
    "cisa-kev": parse_kev,
    "nvd": parse_nvd,
    "feodotracker": parse_feodo,
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
}


def gather(feeds, hits):
    signals = []
    for name in feeds:
        data = _get(FEEDS[name])
        if data is None:
            continue
        try:
            signals.extend(PARSERS[name](data, hits))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            log.warning("parse failed %s: %s", name, exc)
    return signals


def handoff(signals):
    def _fs(s):
        return s["metrics"].get("due" if s["source"] == "cisa-kev" else "first_seen")

    kevs = [s for s in signals if s["source"] == "cisa-kev"]
    iocs = [s for s in signals if s["kind"] == "ioc"]
    return {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "revision": REVISION,
            "counts": {"total": len(signals), "kevs": len(kevs), "iocs": len(iocs)},
            "kevs": [dict(s, first_seen=_fs(s)) for s in kevs][:40],
            "iocs": [dict(s, first_seen=_fs(s)) for s in iocs][:40],
            "top": sorted(signals, key=lambda s: s["score"], reverse=True)[:10]}


def generate_sinkhole(signals):
    """Extract malicious IPs, C2 servers, and malware domains to build DNS/IP sinkhole blocklist (TASK-7.3)."""
    blocked_ips = set()
    blocked_domains = set()
    for s in signals:
        m = s.get("metrics") or {}
        if "ip" in m and m["ip"]:
            blocked_ips.add(str(m["ip"]))
        if s.get("kind") == "malware-url":
            try:
                from urllib.parse import urlparse
                host = urlparse(s.get("url", "")).hostname
                if host and not host.replace(".", "").isdigit():
                    blocked_domains.add(host)
                elif host:
                    blocked_ips.add(host)
            except Exception as exc:
                log.debug("urlparse failed: %s", exc)
        if s.get("kind") == "ioc" and m.get("ioc_type") in ("ip:port", "ipv4"):
            val = str(s.get("title", "")).split()[0]
            ip = val.split(":")[0]
            if ip:
                blocked_ips.add(ip)

    hosts_lines = [
        "# TIANXIA SOVEREIGN THREAT RADAR SINKHOLE",
        f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "# Founder: Collins Takem | Corporate Brand: RASA-X-MACHINA",
        ""
    ]
    for d in sorted(blocked_domains):
        hosts_lines.append(f"0.0.0.0 {d}")
    for ip in sorted(blocked_ips):
        hosts_lines.append(f"# C2_BOTNET_IP: {ip}")

    return {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "blocked_ips_count": len(blocked_ips),
        "blocked_domains_count": len(blocked_domains),
        "blocked_ips": sorted(blocked_ips),
        "blocked_domains": sorted(blocked_domains),
        "hosts_format": "\n".join(hosts_lines) + "\n"
    }


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="live threat-intel ingestion (paper default)")
    ap.add_argument("--feeds", default="all", help="comma list or 'all': " + ",".join(FEEDS))
    ap.add_argument("--hits", type=int, default=int(os.environ.get("TX_THREAT_HITS", "40")))
    ap.add_argument("--apply", action="store_true", help="append signals + write handoff + sinkhole rules")
    args = ap.parse_args(argv)
    if kill_switch():
        log.error("kill-switch engaged; refusing to fetch")
        return 1
    feeds = list(FEEDS) if args.feeds == "all" else [f for f in args.feeds.split(",") if f in FEEDS]
    signals = gather(feeds, args.hits)
    if args.apply:
        try:
            SIGNALS.parent.mkdir(parents=True, exist_ok=True)
            with open(SIGNALS, "a", encoding="utf-8") as fh:
                for sig in signals:
                    fh.write(json.dumps(sig) + "\n")
            HANDOFF.write_text(json.dumps(handoff(signals), indent=2), encoding="utf-8")
            # Generate and seal sinkhole rules (TASK-7.3)
            sink = generate_sinkhole(signals)
            SINKHOLE_HOSTS.parent.mkdir(parents=True, exist_ok=True)
            SINKHOLE_HOSTS.write_text(sink["hosts_format"], encoding="utf-8")
            SINKHOLE_JSON.parent.mkdir(parents=True, exist_ok=True)
            SINKHOLE_JSON.write_text(json.dumps(sink, indent=2), encoding="utf-8")
            log.info("threat sinkhole generated: %d IPs, %d domains -> %s", len(sink["blocked_ips"]), len(sink["blocked_domains"]), SINKHOLE_HOSTS)
        except OSError as exc:
            log.error("apply write failed: %s", exc)
            return 1
    for sig in signals:
        print(json.dumps(sig))
    log.info("rev=%s feeds=%s signals=%d apply=%s", REVISION, feeds, len(signals), args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
