"""Turn check results into exact DNS records to add or replace (the --fix output)."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import checks, providers

Record = Dict[str, str]


def _rec(action: str, rtype: str, host: str, value: str, note: str = "") -> Record:
    r = {"action": action, "type": rtype, "host": host, "value": value}
    if note:
        r["note"] = note
    return r


def _provider(by_name: Dict[str, checks.CheckResult]) -> Optional[str]:
    """Mailbox provider from MX, or guessed from SPF includes when there is no MX."""
    mx = by_name.get("MX")
    p = (mx.details or {}).get("provider") if mx else None
    if p:
        return p
    spf = by_name.get("SPF")
    for inc in ((spf.details or {}).get("includes") or []) if spf else []:
        for name, setup in providers.SETUP.items():
            if providers.spf_authorizes(name, [inc]):
                return name
    return None


def add_include(record: str, include: str) -> str:
    """Insert include:X into an SPF record, before the 'all' or 'redirect' term."""
    terms = record.split()
    if any(t.lower() == f"include:{include}" for t in terms):
        return record
    for i, t in enumerate(terms):
        bare = t.lstrip("+-~?").lower()
        if bare == "all" or bare.startswith("redirect="):
            return " ".join(terms[:i] + [f"include:{include}"] + terms[i:])
    return " ".join(terms + [f"include:{include}", "~all"])


def merge_spf(records: List[str]) -> str:
    """Combine several v=spf1 records into one, keeping the first 'all' qualifier."""
    seen: List[str] = []
    all_term = None
    for rec in records:
        for t in rec.split()[1:]:
            if t.lstrip("+-~?").lower() == "all":
                all_term = all_term or t
            elif t.lower() not in (s.lower() for s in seen):
                seen.append(t)
    return " ".join(["v=spf1"] + seen + [all_term or "~all"])


def _set_tag(record: str, tag: str, value: str) -> str:
    parts = [p.strip() for p in record.split(";") if p.strip()]
    out, done = [], False
    for p in parts:
        k = p.split("=", 1)[0].strip().lower()
        if k == tag:
            out.append(f"{tag}={value}")
            done = True
        else:
            out.append(p)
    if not done:
        out.append(f"{tag}={value}")
    return "; ".join(out)


def plan(domain: str, results: List[checks.CheckResult]) -> None:
    """Attach dns_fixes to the results that need them (in place)."""
    by = {r.name: r for r in results}
    provider = _provider(by)
    setup = providers.SETUP.get(provider or "")

    spf = by.get("SPF")
    if spf and spf.status in (checks.FAIL, checks.WARN):
        record = (spf.details or {}).get("record")
        all_records = (spf.details or {}).get("records")
        if all_records:
            spf.dns_fixes.append(_rec("replace", "TXT", domain, merge_spf(all_records),
                                      "Delete all the existing v=spf1 records and keep only this one."))
        elif not record and setup:
            spf.dns_fixes.append(_rec("add", "TXT", domain, f"v=spf1 include:{setup['spf_include']} ~all",
                                      f"Authorises {provider}. Add includes for any other tool that sends as you."))
        elif record and re.search(r"(^|\s)[+?]?all(\s|$)", record):
            fixed = re.sub(r"(^|\s)[+?]?all(\s|$)", r"\1~all\2", record)
            spf.dns_fixes.append(_rec("replace", "TXT", domain, fixed))
        elif record and spf.status == checks.WARN and "no 'all'" in spf.summary:
            spf.dns_fixes.append(_rec("replace", "TXT", domain, record + " ~all"))

    st = by.get("Setup")
    if st and st.status in (checks.FAIL, checks.WARN) and setup and spf:
        record = (spf.details or {}).get("record")
        if record and not providers.spf_authorizes(provider, (spf.details or {}).get("includes") or []):
            st.dns_fixes.append(_rec("replace", "TXT", domain, add_include(record, setup["spf_include"]),
                                     f"Your current SPF record with {provider} added."))

    dmarc = by.get("DMARC")
    if dmarc and dmarc.status in (checks.FAIL, checks.WARN):
        record = (dmarc.details or {}).get("record")
        host = f"_dmarc.{domain}"
        if not record:
            dmarc.dns_fixes.append(_rec("add", "TXT", host, f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
                                        "Start at p=none, watch the reports for 2 to 4 weeks, then use p=quarantine."))
        elif (dmarc.details or {}).get("inherited_from") is None:
            tags = checks._tags(record)
            if tags.get("p", "").lower() == "none":
                dmarc.dns_fixes.append(_rec("replace", "TXT", host, _set_tag(record, "p", "quarantine"),
                                            "Next step once SPF and DKIM pass in your reports."))
            elif "rua" not in tags:
                dmarc.dns_fixes.append(_rec("replace", "TXT", host,
                                            _set_tag(record, "rua", f"mailto:dmarc@{domain}")))
            elif tags.get("pct", "100") != "100":
                dmarc.dns_fixes.append(_rec("replace", "TXT", host, _set_tag(record, "pct", "100")))

    mx = by.get("MX")
    if mx and mx.status == checks.FAIL and setup and setup.get("mx"):
        for pref, host in setup["mx"]:
            mx.dns_fixes.append(_rec("add", "MX", domain, f"{pref} {host}", f"{provider} mail server"))
