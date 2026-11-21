"""Compare a run against an earlier --save/--json snapshot to catch records that changed or broke."""

from __future__ import annotations

import json
from typing import Dict, List, Tuple

RANK = {"fail": 0, "warn": 1, "pass": 2}


def _fingerprint(check: dict) -> str:
    """The record values that matter for each check, so a silent edit is caught even if status is unchanged."""
    d = check.get("details") or {}
    name = check.get("name")
    if name in ("SPF", "DMARC"):
        return str(d.get("record"))
    if name == "DKIM":
        return ",".join(sorted(k.get("selector", "") for k in d.get("keys") or []))
    if name == "MX":
        return ",".join(d.get("hosts") or [])
    if name == "Domain age":
        return str(d.get("expires"))
    return ""


def load(path: str) -> Dict[str, Dict[str, dict]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    reports = data if isinstance(data, list) else [data]
    return {r["domain"]: {c["name"]: c for c in r.get("checks", [])} for r in reports}


def diff(old: Dict[str, Dict[str, dict]], new_reports: List[dict]) -> Tuple[List[str], bool]:
    """Return (human-readable change lines, whether anything got worse)."""
    lines: List[str] = []
    worse = False
    for rep in new_reports:
        domain = rep["domain"]
        before = old.get(domain)
        if before is None:
            lines.append(f"{domain}: new domain (not in the previous snapshot)")
            continue
        for check in rep.get("checks", []):
            name = check["name"]
            prev = before.get(name)
            if prev is None:
                continue
            a, b = prev.get("status"), check.get("status")
            if a in RANK and b in RANK and RANK[b] < RANK[a]:
                worse = True
                lines.append(f"{domain}: {name} got worse ({a} -> {b}): {check.get('summary')}")
            elif a in RANK and b in RANK and RANK[b] > RANK[a]:
                lines.append(f"{domain}: {name} improved ({a} -> {b})")
            elif _fingerprint(prev) != _fingerprint(check):
                lines.append(f"{domain}: {name} record changed: {_fingerprint(prev)!r} -> {_fingerprint(check)!r}")
    for domain in old:
        if domain not in {r["domain"] for r in new_reports}:
            lines.append(f"{domain}: in the previous snapshot but not checked this time")
    return lines, worse
