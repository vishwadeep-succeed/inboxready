"""Run all checks for a domain and compute a score."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from . import checks
from .dnsutil import Lookup, LookupFailed

WEIGHTS = {"SPF": 25, "DMARC": 25, "DKIM": 20, "Blacklists": 15, "MX": 10, "Website": 5}
FACTOR = {checks.PASS: 1.0, checks.WARN: 0.5, checks.FAIL: 0.0}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    if "@" in d:
        d = d.split("@", 1)[1]
    d = d.split("/")[0].split(":")[0].rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if not DOMAIN_RE.match(d):
        raise ValueError(f"'{raw}' is not a valid domain")
    return d


@dataclass
class Report:
    domain: str
    results: List[checks.CheckResult]
    score: int
    grade: str

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "grade": self.grade,
            "checks": [r.to_dict() for r in self.results],
        }


def grade_for(score: int) -> str:
    for cutoff, g in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= cutoff:
            return g
    return "F"


def score_results(results: List[checks.CheckResult]) -> int:
    earned = total = 0.0
    for r in results:
        w = WEIGHTS.get(r.name)
        if not w or r.status not in FACTOR:
            continue  # info/unknown checks don't count either way
        total += w
        earned += w * FACTOR[r.status]
    return round(100 * earned / total) if total else 0


def domain_exists(lookup: Lookup, domain: str) -> bool:
    for rtype in ("SOA", "NS", "MX", "A", "TXT"):
        try:
            if lookup(domain, rtype):
                return True
        except LookupFailed:
            return True  # can't tell; let the real checks report DNS errors
    return False


def run(domain: str, lookup: Lookup, selectors: Optional[List[str]] = None,
        blacklists: bool = True) -> Report:
    domain = normalize_domain(domain)
    if not domain_exists(lookup, domain):
        r = checks.CheckResult(
            "Domain", checks.FAIL, "Domain not found: it has no DNS records at all.",
            fix="Check the spelling, or register the domain and set up DNS first.",
        )
        return Report(domain, [r], 0, "F")
    results = [
        checks.check_spf(lookup, domain),
        checks.check_dkim(lookup, domain, selectors),
        checks.check_dmarc(lookup, domain),
        checks.check_mx(lookup, domain),
    ]
    if blacklists:
        results.append(checks.check_blacklists(lookup, domain))
    results.append(checks.check_website(lookup, domain))
    results.append(checks.check_extras(lookup, domain))
    score = score_results(results)
    return Report(domain, results, score, grade_for(score))
