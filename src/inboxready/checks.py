"""Deliverability checks. Each check returns a CheckResult."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .dnsutil import Lookup, LookupFailed

PASS, WARN, FAIL, INFO, UNKNOWN = "pass", "warn", "fail", "info", "unknown"


@dataclass
class CheckResult:
    name: str
    status: str
    summary: str
    fix: Optional[str] = None
    details: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"name": self.name, "status": self.status, "summary": self.summary}
        if self.fix:
            d["fix"] = self.fix
        if self.details:
            d["details"] = self.details
        return d


def _txt_records(lookup: Lookup, name: str, prefix: str) -> List[str]:
    return [r.strip() for r in lookup(name, "TXT") if r.strip().lower().startswith(prefix.lower())]


def _tags(record: str) -> Dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


# ---------------------------------------------------------------- SPF

SPF_LOOKUP_MECHS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _count_spf_lookups(lookup: Lookup, domain: str, depth: int = 0, seen=None) -> Tuple[int, List[str]]:
    """Count DNS-querying terms per RFC 7208 section 4.6.4, following includes."""
    seen = seen if seen is not None else set()
    problems: List[str] = []
    if depth > 10 or domain in seen:
        return 0, problems
    seen.add(domain)
    try:
        records = _txt_records(lookup, domain, "v=spf1")
    except LookupFailed:
        problems.append(f"could not fetch SPF for {domain}")
        return 0, problems
    if not records:
        if depth > 0:
            problems.append(f"included domain {domain} has no SPF record (void lookup)")
        return 0, problems
    count = 0
    for term in records[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:"):
            count += 1
            sub, p = _count_spf_lookups(lookup, t.split(":", 1)[1], depth + 1, seen)
            count += sub
            problems += p
        elif t.startswith("redirect="):
            count += 1
            sub, p = _count_spf_lookups(lookup, t.split("=", 1)[1], depth + 1, seen)
            count += sub
            problems += p
        elif t in ("a", "mx", "ptr") or re.match(r"^(a|mx|ptr)[:/]", t) or t.startswith("exists:"):
            count += 1
    return count, problems


def check_spf(lookup: Lookup, domain: str) -> CheckResult:
    try:
        records = _txt_records(lookup, domain, "v=spf1")
    except LookupFailed as exc:
        return CheckResult("SPF", UNKNOWN, str(exc))
    if not records:
        return CheckResult(
            "SPF", FAIL, "No SPF record found.",
            fix=f'Add a TXT record on {domain} such as "v=spf1 include:_spf.google.com ~all" '
                "(swap in the include for your email provider).",
        )
    if len(records) > 1:
        return CheckResult(
            "SPF", FAIL, f"{len(records)} SPF records found. Receivers treat this as a permanent error.",
            fix="Merge them into a single v=spf1 TXT record.",
            details={"records": records},
        )
    record = records[0]
    terms = [t.lower() for t in record.split()[1:]]
    count, problems = _count_spf_lookups(lookup, domain)
    details = {"record": record, "dns_lookups": count}
    if problems:
        details["notes"] = problems

    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    has_redirect = any(t.startswith("redirect=") for t in terms)

    if count > 10:
        return CheckResult(
            "SPF", FAIL, f"SPF needs {count} DNS lookups; the limit is 10, so SPF fails at receivers.",
            fix="Remove includes for tools you no longer send from, or flatten the record.",
            details=details,
        )
    if all_term in ("all", "+all"):
        return CheckResult(
            "SPF", FAIL, "SPF ends in +all, which lets anyone send as your domain.",
            fix="Change +all to ~all (soft fail) or -all (hard fail).", details=details,
        )
    if all_term is None and not has_redirect:
        return CheckResult(
            "SPF", WARN, "SPF has no 'all' mechanism, so unlisted senders get a neutral result.",
            fix="End the record with ~all or -all.", details=details,
        )
    if all_term == "?all":
        return CheckResult(
            "SPF", WARN, "SPF ends in ?all (neutral), which gives receivers no guidance.",
            fix="Use ~all or -all instead.", details=details,
        )
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        return CheckResult(
            "SPF", WARN, "SPF uses the deprecated ptr mechanism.",
            fix="Replace ptr with explicit ip4/ip6 or include terms.", details=details,
        )
    if count >= 8:
        return CheckResult(
            "SPF", WARN, f"SPF is valid but uses {count}/10 DNS lookups. One more tool could break it.",
            fix="Trim unused includes before adding another sending tool.", details=details,
        )
    return CheckResult("SPF", PASS, f"Valid SPF record ({count}/10 DNS lookups).", details=details)


# ---------------------------------------------------------------- DMARC

def _org_domain(domain: str) -> str:
    # Simple heuristic; good enough for most cold-email sending domains.
    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def check_dmarc(lookup: Lookup, domain: str) -> CheckResult:
    try:
        records = _txt_records(lookup, f"_dmarc.{domain}", "v=dmarc1")
        source = domain
        if not records and _org_domain(domain) != domain:
            source = _org_domain(domain)
            records = _txt_records(lookup, f"_dmarc.{source}", "v=dmarc1")
    except LookupFailed as exc:
        return CheckResult("DMARC", UNKNOWN, str(exc))

    if not records:
        return CheckResult(
            "DMARC", FAIL,
            "No DMARC record. Google and Yahoo require DMARC for bulk senders since 2024.",
            fix=f'Add a TXT record at _dmarc.{domain}: "v=DMARC1; p=none; rua=mailto:dmarc@{domain}" '
                "then move to p=quarantine once reports look clean.",
        )
    if len(records) > 1:
        return CheckResult("DMARC", FAIL, "More than one DMARC record found; receivers ignore both.",
                           fix="Keep exactly one v=DMARC1 record.", details={"records": records})

    record = records[0]
    tags = _tags(record)
    details = {"record": record}
    if source != domain:
        details["inherited_from"] = source
    policy = tags.get("p", "").lower()
    pct = tags.get("pct", "100")

    if policy not in ("none", "quarantine", "reject"):
        return CheckResult("DMARC", FAIL, "DMARC record has no valid p= policy.",
                           fix="Set p=none, p=quarantine or p=reject.", details=details)
    if policy == "none":
        return CheckResult(
            "DMARC", WARN, "DMARC is p=none (monitoring only). It passes the Gmail/Yahoo rule but "
            "does not protect your domain from spoofing.",
            fix="Once SPF and DKIM pass in your reports, move to p=quarantine.", details=details,
        )
    if pct.isdigit() and int(pct) < 100:
        return CheckResult("DMARC", WARN, f"DMARC p={policy} but only applied to {pct}% of mail.",
                           fix="Raise pct to 100 when you are confident.", details=details)
    if "rua" not in tags:
        return CheckResult("DMARC", WARN, f"DMARC p={policy} but no rua= address, so you get no reports.",
                           fix=f"Add rua=mailto:dmarc@{domain} to the record.", details=details)
    return CheckResult("DMARC", PASS, f"DMARC enforced with p={policy}.", details=details)


# ---------------------------------------------------------------- DKIM

COMMON_SELECTORS = [
    "google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3",
    "s1", "s2", "smtp", "mandrill", "mxvm", "zoho", "zmail", "pm", "everlytickey1",
    "sig1", "protonmail", "fm1", "fm2", "mailjet", "brevo1", "brevo2", "hs1", "hs2",
    "sm", "mta", "key1", "dkim1", "ses",
]


def _der_read(buf: bytes, i: int) -> Tuple[int, int, int]:
    """Read one DER TLV at i. Returns (tag, content_start, content_end)."""
    tag = buf[i]
    length = buf[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    return tag, i, i + length


def _rsa_bits(p: str) -> Optional[int]:
    """Exact RSA modulus size from a DKIM p= value (SPKI or PKCS#1 form)."""
    try:
        raw = base64.b64decode(re.sub(r"\s", "", p) + "=" * (-len(p) % 4))
        tag, s, e = _der_read(raw, 0)  # outer SEQUENCE
        tag, s2, e2 = _der_read(raw, s)
        if tag == 0x30:  # SPKI: AlgorithmIdentifier, then BIT STRING
            tag, s3, e3 = _der_read(raw, e2)
            if tag != 0x03:
                return None
            _, s4, _ = _der_read(raw, s3 + 1)  # skip unused-bits byte, inner SEQUENCE
            tag, ms, me = _der_read(raw, s4)  # modulus INTEGER
        elif tag == 0x02:  # PKCS#1 RSAPublicKey: modulus INTEGER first
            ms, me = s2, e2
        else:
            return None
        modulus = raw[ms:me].lstrip(b"\x00")
        return int.from_bytes(modulus, "big").bit_length()
    except (binascii.Error, ValueError, IndexError):
        return None


def check_dkim(lookup: Lookup, domain: str, selectors: Optional[List[str]] = None) -> CheckResult:
    user_given = bool(selectors)
    to_try = selectors or COMMON_SELECTORS
    found = []
    failures = 0
    for sel in to_try:
        try:
            recs = lookup(f"{sel}._domainkey.{domain}", "TXT")
        except LookupFailed:
            failures += 1
            continue
        for rec in recs:
            tags = _tags(rec)
            if "p" not in tags and "v" not in tags and "k" not in tags:
                continue
            key = tags.get("p", "")
            k = tags.get("k", "rsa").lower()
            entry = {"selector": sel, "key_type": k, "revoked": key == ""}
            if key and k == "rsa":
                entry["bits"] = _rsa_bits(key)
            found.append(entry)
            break

    if failures == len(to_try):
        return CheckResult("DKIM", UNKNOWN, "DNS failed for every DKIM selector lookup.")
    active = [f for f in found if not f["revoked"]]
    if not active:
        if user_given:
            return CheckResult(
                "DKIM", FAIL, f"No DKIM key found for selector(s): {', '.join(to_try)}.",
                fix="Generate a DKIM key in your email provider and publish the TXT record it gives you.",
                details={"selectors_checked": to_try},
            )
        return CheckResult(
            "DKIM", WARN,
            "No DKIM key found on common selectors. You may use a custom selector.",
            fix="Find the selector in a sent email header (DKIM-Signature: s=...) and re-run with "
                "--selector NAME. If DKIM is not set up, enable it in your email provider.",
            details={"selectors_checked": len(to_try)},
        )
    weak = [f for f in active if f.get("bits") and f["bits"] < 2048]
    if weak:
        return CheckResult(
            "DKIM", WARN,
            f"DKIM found ({', '.join(f['selector'] for f in active)}) but key is {weak[0]['bits']}-bit.",
            fix="Rotate to a 2048-bit DKIM key in your email provider.", details={"keys": active},
        )
    return CheckResult("DKIM", PASS, f"DKIM key found: {', '.join(f['selector'] for f in active)}.",
                       details={"keys": active})


# ---------------------------------------------------------------- MX

PROVIDERS = {
    "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365", "zoho.com": "Zoho", "zoho.in": "Zoho", "zoho.eu": "Zoho",
    "protonmail.ch": "Proton", "messagingengine.com": "Fastmail", "mimecast.com": "Mimecast",
    "pphosted.com": "Proofpoint", "secureserver.net": "GoDaddy", "titan.email": "Titan",
    "icloud.com": "iCloud", "yandex.net": "Yandex", "amazonaws.com": "Amazon SES",
}


def check_mx(lookup: Lookup, domain: str) -> CheckResult:
    try:
        records = lookup(domain, "MX")
    except LookupFailed as exc:
        return CheckResult("MX", UNKNOWN, str(exc))
    if not records:
        return CheckResult(
            "MX", FAIL, "No MX records. You cannot receive replies, and many filters distrust such domains.",
            fix="Add MX records for your mailbox provider so replies reach you.",
        )
    parsed = []
    for r in records:
        pref, _, host = r.strip().partition(" ")
        parsed.append((int(pref) if pref.isdigit() else 0, host.strip().rstrip(".").lower()))
    parsed.sort()
    names = [h for _, h in parsed if h]
    if not names:
        return CheckResult("MX", FAIL, "Domain publishes a null MX (accepts no mail).",
                           fix="Replace the null MX with your mailbox provider's MX records.")
    provider = next((p for suffix, p in PROVIDERS.items() for n in names if n.endswith(suffix)), None)
    summary = f"{len(names)} MX record(s)" + (f", hosted on {provider}." if provider else ".")
    return CheckResult("MX", PASS, summary, details={"hosts": names, "provider": provider})


# ---------------------------------------------------------------- Blacklists

DOMAIN_BLS = {
    "dbl.spamhaus.org": lambda ip: ip.startswith("127.0.1."),
    "multi.uribl.com": lambda ip: ip.startswith("127.0.0.") and ip != "127.0.0.1",
    "multi.surbl.org": lambda ip: ip.startswith("127.0.0.") and ip != "127.0.0.1",
}
IP_BLS = {
    "zen.spamhaus.org": lambda ip: ip.startswith("127.0.0.") and 2 <= int(ip.split(".")[-1]) <= 11,
    "bl.spamcop.net": lambda ip: ip == "127.0.0.2",
    "b.barracudacentral.org": lambda ip: ip == "127.0.0.2",
}


def _query_bl(lookup: Lookup, qname: str, is_listed) -> str:
    try:
        answers = lookup(qname, "A")
    except LookupFailed:
        return "error"
    if not answers:
        return "clean"
    if any(is_listed(a) for a in answers):
        return "listed"
    return "blocked"  # e.g. Spamhaus 127.255.255.x: query refused via public resolver


def check_blacklists(lookup: Lookup, domain: str) -> CheckResult:
    results: Dict[str, str] = {}
    for bl, fn in DOMAIN_BLS.items():
        results[f"{domain} @ {bl}"] = _query_bl(lookup, f"{domain}.{bl}", fn)

    ips = set()
    try:
        for mx in lookup(domain, "MX")[:2]:
            host = mx.strip().partition(" ")[2].strip()
            if not host or host == ".":
                continue
            for ip in lookup(host, "A")[:2]:
                ips.add(ip)
    except LookupFailed:
        pass
    for ip in sorted(ips):
        rev = ".".join(reversed(ip.split(".")))
        for bl, fn in IP_BLS.items():
            results[f"{ip} @ {bl}"] = _query_bl(lookup, f"{rev}.{bl}", fn)

    listed = [k for k, v in results.items() if v == "listed"]
    usable = [k for k, v in results.items() if v in ("clean", "listed")]
    details = {"results": results}
    if listed:
        return CheckResult(
            "Blacklists", FAIL, f"Listed on {len(listed)} blocklist(s): {', '.join(listed)}.",
            fix="Stop sending from this domain, find the cause (bad list, spam complaints), then request "
                "delisting on each blocklist's website.",
            details=details,
        )
    if not usable:
        return CheckResult(
            "Blacklists", UNKNOWN,
            "Blocklists refused the queries (common on public DNS like 8.8.8.8).",
            fix="Re-run from a network with its own resolver, or use --nameserver.",
            details=details,
        )
    return CheckResult("Blacklists", PASS, f"Clean on {len(usable)} blocklist checks.", details=details)


# ---------------------------------------------------------------- Website

def check_website(lookup: Lookup, domain: str) -> CheckResult:
    try:
        a = lookup(domain, "A") or lookup(f"www.{domain}", "A") or lookup(domain, "AAAA")
    except LookupFailed as exc:
        return CheckResult("Website", UNKNOWN, str(exc))
    if not a:
        return CheckResult(
            "Website", WARN,
            "Domain has no website. Prospects who check a cold sender's domain find nothing.",
            fix="Point the domain at a simple page or redirect it to your main site.",
        )
    return CheckResult("Website", PASS, "Domain resolves to a website.", details={"addresses": a[:3]})


# ---------------------------------------------------------------- Extras (info only)

def check_extras(lookup: Lookup, domain: str) -> CheckResult:
    found = {}
    try:
        found["MTA-STS"] = bool(_txt_records(lookup, f"_mta-sts.{domain}", "v=stsv1"))
        found["TLS-RPT"] = bool(_txt_records(lookup, f"_smtp._tls.{domain}", "v=tlsrptv1"))
        found["BIMI"] = bool(_txt_records(lookup, f"default._bimi.{domain}", "v=bimi1"))
    except LookupFailed as exc:
        return CheckResult("Extras", UNKNOWN, str(exc))
    have = [k for k, v in found.items() if v]
    summary = f"Has {', '.join(have)}." if have else "No MTA-STS, TLS-RPT or BIMI (optional, nice to have)."
    return CheckResult("Extras", INFO, summary, details=found)
