#!/usr/bin/env python3
# ffp: FFP-GH-REPO-SENTINEL concurrent-daemon python
"""
tx_github_repo_sentinel.py — Autonomous GitHub Repository Update Sentinel
Coupled to `tx_scour`, `tx_opportunities_miner`, `tx_security_scour`, `tx_security_miner` & `tx_website_live_sync`.

Responsibilities:
  1. Polls all active repositories across `@Tianxia-Core`, `@Tianxia-Presence`, `@Tianxia-Revenues`,
     and `@collinstaken525-cloud`, computing a deterministic SHA-256 ecosystem state digest.
  2. Whenever repository commits, SemVer releases, or open PRs change (or `--force` is passed):
     - Runs `tx_scour.py` (commercial/research/x402 signal harvest)
     - Runs `tx_security_scour.py` (CISA KEV, OSV supply-chain, TLS 1.3 headers, GitHub & 0600 vault scour)
     - Runs `tx_opportunities_miner.py` (RGU SFI matrix refresh)
     - Runs `tx_security_miner.py` (Security Hardening Index `SHI` & defensive sprint matrix)
     - Sweeps open PRs via `tx_git_automerge.py sweep --auto-merge` (14-Gate differential review)
     - Pushes live repo & service updates to `rasaxmachina.com` via `tx_website_live_sync.py --deploy`
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

THIS_DIR = Path(__file__).resolve().parent
TIANXIA_DIR = THIS_DIR.parent
STATE_FILE = TIANXIA_DIR / "config" / "github_repo_sentinel_state.json"
ORGS = ["Tianxia-Core", "Tianxia-Presence", "Tianxia-Revenues", "collinstaken525-cloud"]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot_github_ecosystem() -> dict[str, Any]:
    repos: list[dict[str, Any]] = []
    for org in ORGS:
        proc = subprocess.run(
            [
                "gh", "repo", "list", org, "--limit", "40",
                "--json", "nameWithOwner,pushedAt,latestRelease,isArchived,defaultBranchRef",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        for r in json.loads(proc.stdout):
            if r.get("isArchived"):
                continue
            rel = (r.get("latestRelease") or {}).get("tagName") or "NONE"
            oid = (((r.get("defaultBranchRef") or {}).get("target") or {}).get("oid")) or ""
            repos.append({
                "repo": r["nameWithOwner"],
                "head_oid": oid[:12],
                "pushed_at": r.get("pushedAt") or "",
                "latest_release": rel,
            })
    repos.sort(key=lambda x: x["repo"])
    digest = hashlib.sha256(json.dumps(repos, sort_keys=True).encode("utf-8")).hexdigest()
    return {"digest": digest, "repos": repos}


def run_step(script_name: str, args: list[str], timeout: int = 90) -> dict[str, Any]:
    script = THIS_DIR / script_name
    if not script.is_file():
        return {"ok": False, "error": f"missing_{script_name}"}
    proc = subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {"ok": proc.returncode == 0, "rc": proc.returncode}


def main() -> int:
    ap = argparse.ArgumentParser(description="Autonomous GitHub Repo Update Sentinel")
    ap.add_argument("--force", action="store_true", help="Execute full coupled pipeline even if repo digest is unchanged")
    ap.add_argument("--deploy-web", action="store_true", help="Deploy live website updates to Hub & Edge when syncing")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    snap = snapshot_github_ecosystem()
    prev_digest = ""
    if STATE_FILE.is_file():
        try:
            prev_digest = json.loads(STATE_FILE.read_text(encoding="utf-8")).get("ecosystem_sha256", "")
        except ValueError:
            prev_digest = ""

    changed = (snap["digest"] != prev_digest) or args.force
    pipeline: dict[str, Any] = {}

    if changed:
        pipeline["tx_scour"] = run_step("tx_scour.py", ["x402"], timeout=45)
        pipeline["tx_security_scour"] = run_step("tx_security_scour.py", ["all", "--json"], timeout=45)
        pipeline["tx_opportunities_miner"] = run_step("tx_opportunities_miner.py", ["matrix"], timeout=45)
        pipeline["tx_security_miner"] = run_step("tx_security_miner.py", ["matrix", "--json"], timeout=45)
        pipeline["tx_git_automerge_sweep"] = run_step("tx_git_automerge.py", ["sweep", "--auto-merge"], timeout=60)
        web_args = ["--json", "--deploy"] if args.deploy_web else ["--json"]
        pipeline["tx_website_live_sync"] = run_step("tx_website_live_sync.py", web_args, timeout=60)

    unreleased = [
        r["repo"] for r in snap["repos"]
        if r["latest_release"] == "NONE" and not r["repo"].endswith("/.github") and r["repo"] != "collinstaken525-cloud/collinstaken525-cloud"
    ]

    state_doc = {
        "ok": True,
        "checked_at": utc_now(),
        "ecosystem_sha256": snap["digest"],
        "changed_or_forced": changed,
        "repositories_tracked": len(snap["repos"]),
        "unreleased_product_repos": unreleased,
        "pipeline": pipeline,
        "repos": snap["repos"],
    }
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".repo_sentinel.", suffix=".tmp", dir=str(STATE_FILE.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(state_doc, indent=2) + "\n")
    os.replace(tmp, STATE_FILE)

    if args.json:
        print(json.dumps(state_doc, indent=2))
    else:
        print(
            f"[tx_github_repo_sentinel] repos={len(snap['repos'])} changed={changed} "
            f"unreleased={len(unreleased)} digest={snap['digest'][:12]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
