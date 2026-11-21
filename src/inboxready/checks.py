"""Deliverability checks. Each check returns a CheckResult."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from . import providers, rdap
from .dnsutil import Lookup, LookupFailed

PASS, WARN, FAIL, INFO, UNKNOWN = "pass", "warn", "fail", "info", "unknown"


@dataclass
class CheckResult:
    name: str
    status: str
    summary: str
    fix: Optional[str] = None
    details: Dict[str, object] = field(default_factory=dict)
    dns_fixes: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {"name": self.name, "status": self.status, "summary": self.summary}
        if self.fix:
            d["fix"] = self.fix
        if self.dns_fixes:
            d["dns_fixes"] = self.dns_fixes
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

SPF_RE = re.compile(r"^v=spf1(\s|$)", re.I)
SPF_MECHS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
MODIFIER_RE = re.compile(r"^[a-z][a-z0-9_.-]*$")
CIDR_RE = re.compile(r"^(?:/(\d{1,2}))?(?://(\d{1,3}))?$")


def _spf_records(lookup: Lookup, name: str) -> List[str]:
    return [r.strip() for r in lookup(name, "TXT") if SPF_RE.match(r.strip())]


def _spf_term_error(term: str) -> Optional[str]:
    """Return a description of a syntax error in one SPF term, or None if it is valid."""
    t = term[1:] if term[:1] in "+-~?" else term
    tl = t.lower()
    if "=" in tl and not tl.startswith(("ip4:", "ip6:", "a:", "mx:", "include:", "exists:", "ptr:")):
        name, _, value = tl.partition("=")
        if not MODIFIER_RE.match(name):
            return f"'{term}' is not a valid modifier"
        if name in ("redirect", "exp") and not value:
            return f"'{term}' needs a domain"
        return None
    m = re.match(r"^([a-z0-9]+)(.*)$", tl)
    if not m or m.group(1) not in SPF_MECHS:
        return f"unknown mechanism '{term}'"
    mech, rest = m.groups()
    if mech == "all":
        return None if rest == "" else f"'{term}' takes no arguments"
    if mech in ("ip4", "ip6"):
        if not rest.startswith(":"):
            return f"'{term}' needs an address"
        try:
            net = ipaddress.ip_network(rest[1:], strict=False)
        except ValueError:
            return f"'{term}' has an invalid IP address or range"
        if (mech == "ip4") != (net.version == 4):
            return f"'{term}' uses the wrong IP version"
        return None
    if mech in ("include", "exists"):
        return None if rest.startswith(":") and len(rest) > 1 else f"'{term}' needs a domain"
    # a, mx, ptr: optional :domain, then optional /cidr (a and mx only)
    domain_part, cidr = rest, ""
    idx = rest.find("/")
    if idx != -1:
        domain_part, cidr = rest[:idx], rest[idx:]
    if domain_part and (not domain_part.startswith(":") or len(domain_part) == 1):
        return f"'{term}' is malformed"
    if cidr:
        if mech == "ptr":
            return f"'{term}' cannot have a prefix length"
        c = CIDR_RE.match(cidr)
        if not c or (c.group(1) and int(c.group(1)) > 32) or (c.group(2) and int(c.group(2)) > 128):
            return f"'{term}' has an invalid prefix length"
    return None


@dataclass
class _SpfWalk:
    lookups: int = 0
    voids: int = 0
    includes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _walk_spf(lookup: Lookup, domain: str, walk: _SpfWalk, stack: Tuple[str, ...] = ()) -> None:
    """Follow an SPF record and its includes, counting lookups and collecting permanent errors."""
    domain = domain.lower().rstrip(".")
    if domain in stack:
        walk.errors.append(f"include loop: {' -> '.join(stack + (domain,))}")
        return
    if len(stack) > 10 or walk.lookups > 20:
        return
    try:
        records = _spf_records(lookup, domain)
    except LookupFailed:
        walk.notes.append(f"could not fetch SPF for {domain}")
        return
    where = "" if not stack else f" (in {domain})"
    if not records:
        if stack:
            walk.voids += 1
            walk.errors.append(f"{domain} is included but has no SPF record")
        return
    if len(records) > 1:
        walk.errors.append(f"{domain} has {len(records)} SPF records")
        return
    terms = records[0].split()[1:]
    has_all = False
    redirect = None
    for term in terms:
        err = _spf_term_error(term)
        if err:
            walk.errors.append(err + where)
            continue
        t = term.lstrip("+-~?").lower()
        if t == "all":
            has_all = True
        elif t.startswith("redirect="):
            redirect = t.split("=", 1)[1]
        elif t.startswith("include:"):
            walk.lookups += 1
            target = t.split(":", 1)[1]
            walk.includes.append(target)
            if "%" in target:
                walk.notes.append(f"skipped macro include {target}")
            else:
                _walk_spf(lookup, target, walk, stack + (domain,))
        elif re.match(r"^(a|mx|ptr)(:|/|$)", t) or t.startswith("exists:"):
            walk.lookups += 1
    if redirect:
        if has_all:
            walk.notes.append(f"redirect={redirect} is ignored because the record has an 'all' term{where}")
        else:
            walk.lookups += 1
            walk.includes.append(redirect)
            _walk_spf(lookup, redirect, walk, stack + (domain,))


def check_spf(lookup: Lookup, domain: str) -> CheckResult:
    try:
        records = _spf_records(lookup, domain)
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
    walk = _SpfWalk()
    _walk_spf(lookup, domain, walk)
    count = walk.lookups
    details = {"record": record, "dns_lookups": count, "includes": walk.includes}
    if walk.notes:
        details["notes"] = walk.notes

    if walk.errors:
        details["errors"] = walk.errors
        return CheckResult(
            "SPF", FAIL, f"SPF has an error, so receivers treat it as invalid: {walk.errors[0]}.",
            fix="Correct that term, or remove includes for services you no longer use.",
            details=details,
        )
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    has_redirect = any(t.startswith("redirect=") for t in terms)

    if count > 10:
        return CheckResult(
            "SPF", FAIL, f"SPF needs {count} DNS lookups; the limit is 10, so SPF fails at receivers.",
            fix="Remove includes for tools you no longer send from, or flatten the record.",
            details=details,
        )
    if walk.voids > 2:
        return CheckResult(
            "SPF", FAIL, f"SPF has {walk.voids} lookups that return nothing; more than 2 is an error.",
            fix="Remove includes that point at domains without SPF records.", details=details,
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

DMARC_RE = re.compile(r"^v\s*=\s*dmarc1\s*(;|$)", re.I)


def _find_dmarc(lookup: Lookup, domain: str) -> Tuple[Optional[str], List[str]]:
    """DMARCbis tree walk: try _dmarc at the domain, then each parent (max 8 queries, never the TLD)."""
    labels = domain.split(".")
    tried = 0
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        recs = [r.strip() for r in lookup(f"_dmarc.{name}", "TXT") if DMARC_RE.match(r.strip())]
        tried += 1
        if recs:
            return name, recs
        if tried >= 8:
            break
    return None, []


def check_dmarc(lookup: Lookup, domain: str) -> CheckResult:
    try:
        source, records = _find_dmarc(lookup, domain)
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
    inherited = source != domain
    if inherited:
        details["inherited_from"] = source
    raw_p = tags.get("p", "").lower()
    # A subdomain that inherits a parent's record gets the sp= policy if one is set.
    policy = tags.get("sp", raw_p).lower() if inherited else raw_p
    if inherited and "sp" in tags:
        details["subdomain_policy"] = policy
    pct = tags.get("pct", "100")

    if raw_p not in ("none", "quarantine", "reject") or policy not in ("none", "quarantine", "reject"):
        return CheckResult("DMARC", FAIL, "DMARC record has no valid p= policy.",
                           fix="Set p=none, p=quarantine or p=reject.", details=details)
    label = f"sp={policy} (inherited from {source})" if inherited and "sp" in tags else f"p={policy}"
    if policy == "none":
        return CheckResult(
            "DMARC", WARN, f"DMARC is {label}, monitoring only. It passes the Gmail/Yahoo rule but "
            "does not protect your domain from spoofing.",
            fix="Once SPF and DKIM pass in your reports, move to p=quarantine.", details=details,
        )
    if pct.isdigit() and int(pct) < 100:
        return CheckResult("DMARC", WARN, f"DMARC {label} but only applied to {pct}% of mail.",
                           fix="Raise pct to 100 when you are confident.", details=details)
    if "rua" not in tags:
        return CheckResult("DMARC", WARN, f"DMARC {label} but no rua= address, so you get no reports.",
                           fix=f"Add rua=mailto:dmarc@{source} to the record.", details=details)
    return CheckResult("DMARC", PASS, f"DMARC enforced with {label}.", details=details)


# ---------------------------------------------------------------- DKIM

COMMON_SELECTORS = [
    "google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "k3",
    "s1", "s2", "smtp", "mandrill", "mxvm", "zoho", "zmail", "pm", "everlytickey1",
    "sig1", "protonmail", "fm1", "fm2", "mailjet", "brevo1", "brevo2", "hs1", "hs2",
    "sm", "mta", "key1", "dkim1", "ses", "dkim2", "cm", "smtpapi", "20230601", "20221208",
    "20210112", "20161025",
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
    if i + length > len(buf):
        raise ValueError("truncated key")
    return tag, i, i + length


def _rsa_bits(p: str) -> Optional[int]:
    """Exact RSA modulus size from a DKIM p= value (SPKI or PKCS#1 form)."""
    try:
        p = re.sub(r"\s", "", p)
        raw = base64.b64decode(p + "=" * (-len(p) % 4))
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
    to_try = list(selectors or COMMON_SELECTORS)

    def probe(sel: str):
        try:
            recs = lookup(f"{sel}._domainkey.{domain}", "TXT")
        except LookupFailed:
            return None  # DNS error
        for rec in recs:
            tags = _tags(rec)
            if "p" not in tags or tags.get("v", "DKIM1").upper() != "DKIM1":
                continue
            key = re.sub(r"\s", "", tags["p"])
            k = tags.get("k", "rsa").lower()
            entry = {"selector": sel, "key_type": k, "revoked": key == ""}
            if key and k == "rsa":
                entry["bits"] = _rsa_bits(key)
                if entry["bits"] is None:
                    entry["broken"] = True
            return entry
        return False  # no key

    # One random selector tells us if the domain answers for *every* selector (wildcard).
    canary = "inboxready-" + secrets.token_hex(4)
    with ThreadPoolExecutor(max_workers=min(16, len(to_try) + 1)) as pool:
        results = list(pool.map(probe, to_try + [canary]))
    canary_result = results.pop()
    wildcard = bool(canary_result)
    failures = sum(1 for r in results if r is None)
    found = [r for r in results if r]
    if wildcard and canary_result.get("revoked") and not user_given:
        return CheckResult(
            "DKIM", FAIL,
            "Domain publishes an empty DKIM key for every selector, which declares that it never signs mail.",
            fix="If you send from this domain, remove the wildcard *._domainkey record and publish your "
                "provider's DKIM key.",
        )
    if wildcard and not user_given:
        return CheckResult(
            "DKIM", UNKNOWN,
            "This domain answers every DKIM selector (wildcard record), so selectors can't be guessed.",
            fix="Find your selector in a sent email header (DKIM-Signature: s=...) and re-run with --selector NAME.",
        )

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
    broken = [f for f in active if f.get("broken")]
    good = [f for f in active if not f.get("broken")]
    weak = [f for f in good if f.get("bits") and f["bits"] < 1024]
    if not good:
        return CheckResult(
            "DKIM", FAIL,
            f"DKIM record found ({', '.join(f['selector'] for f in broken)}) but the key is cut off or malformed, "
            "so signatures can't be verified.",
            fix="Re-copy the full DKIM value from your email provider. Long keys must be pasted completely; "
                "some DNS hosts need it split into 255-character strings.",
            details={"keys": active},
        )
    if broken or weak:
        problems = [f"{f['selector']} (broken key)" for f in broken]
        problems += [f"{f['selector']} ({f['bits']}-bit, too weak)" for f in weak]
        return CheckResult(
            "DKIM", WARN,
            f"DKIM works on {len(good) - len(weak)} selector(s), but has problems on: {', '.join(problems)}.",
            fix="Re-publish broken keys in full, and rotate keys under 1024 bits to 2048-bit keys.",
            details={"keys": active},
        )
    names = ", ".join(f["selector"] for f in good)
    small = [f["selector"] for f in good if f.get("bits") == 1024]
    tip = f" Tip: {', '.join(small)} use 1024-bit keys; 2048-bit is recommended." if small else ""
    return CheckResult("DKIM", PASS, f"DKIM key found: {names}.{tip}", details={"keys": active})


# ---------------------------------------------------------------- MX

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
    provider = providers.mailbox_provider(names)
    summary = f"{len(names)} MX record(s)" + (f", hosted on {provider}." if provider else ".")
    return CheckResult("MX", PASS, summary, details={"hosts": names, "provider": provider})


# ---------------------------------------------------------------- Blacklists

# Each classifier maps a blocklist answer to (verdict, meaning). Verdicts:
#   listed  = a real listing that hurts delivery
#   caution = the domain was abused, or is in a grey area (worth knowing, not a block)
#   ignore  = a code that does not matter for this use
#   blocked = the list refused to answer (public resolver, rate limit)

def _spamhaus_dbl(ip: str) -> Tuple[str, str]:
    codes = {"2": "spam domain", "4": "phishing domain", "5": "malware domain", "6": "botnet C&C domain"}
    if ip.startswith("127.0.1."):
        last = ip.rsplit(".", 1)[1]
        if last in codes:
            return "listed", codes[last]
        if last.startswith("1") and len(last) == 3 and last != "255":
            return "caution", "legitimate domain whose links were abused by spammers"
    return "blocked", f"query refused ({ip})"


def _uribl(ip: str) -> Tuple[str, str]:
    if not ip.startswith("127.0.0."):
        return "blocked", f"query refused ({ip})"
    bits = int(ip.rsplit(".", 1)[1])
    if bits == 1:
        return "blocked", "query refused (public resolver)"
    if bits & 2 or bits & 8:
        return "listed", "black list" if bits & 2 else "red list (newly abused)"
    if bits & 4:
        return "caution", "grey list (bulk sender, not a spam listing)"
    return "ignore", f"code {ip}"


def _surbl(ip: str) -> Tuple[str, str]:
    if not ip.startswith("127.0.0."):
        return "blocked", f"query refused ({ip})"
    bits = int(ip.rsplit(".", 1)[1])
    if bits <= 1:
        return "blocked", "query refused"
    return "listed", "SURBL listing"


def _zen(ip: str) -> Tuple[str, str]:
    if not ip.startswith("127.0.0."):
        return "blocked", f"query refused ({ip})"
    last = int(ip.rsplit(".", 1)[1])
    if last in (10, 11):
        return "ignore", "policy list for end-user IPs (not a spam listing)"
    if last == 2:
        return "listed", "SBL spam source"
    if last == 3:
        return "listed", "CSS low-reputation sender"
    if 4 <= last <= 7:
        return "listed", "XBL compromised host"
    if last == 9:
        return "listed", "DROP hijacked network"
    return "ignore", f"code {ip}"


def _simple(ip: str) -> Tuple[str, str]:
    return ("listed", "listed") if ip == "127.0.0.2" else ("ignore", f"code {ip}")


DOMAIN_BLS = {"dbl.spamhaus.org": _spamhaus_dbl, "multi.uribl.com": _uribl, "multi.surbl.org": _surbl}
IP_BLS = {"zen.spamhaus.org": _zen, "bl.spamcop.net": _simple, "b.barracudacentral.org": _simple}


def _query_bl(lookup: Lookup, qname: str, classify) -> Tuple[str, str]:
    try:
        answers = lookup(qname, "A")
    except LookupFailed:
        return "error", "lookup failed"
    if not answers:
        return "clean", ""
    order = ["listed", "caution", "ignore", "blocked"]
    results = sorted((classify(a) for a in answers), key=lambda r: order.index(r[0]))
    return results[0]


def _sending_ips(lookup: Lookup, domain: str) -> List[str]:
    """Single IPv4 addresses the domain's own SPF record authorises (its own servers or relays)."""
    try:
        recs = _spf_records(lookup, domain)
    except LookupFailed:
        return []
    ips = []
    for term in (recs[0].split() if recs else []):
        t = term.lstrip("+~?").lower()
        if t.startswith("ip4:"):
            value = t[4:]
            if "/" in value and not value.endswith("/32"):
                continue
            ips.append(value.split("/")[0])
    return ips[:4]


def check_blacklists(lookup: Lookup, domain: str) -> CheckResult:
    results: Dict[str, Tuple[str, str]] = {}
    for bl, fn in DOMAIN_BLS.items():
        results[f"{domain} @ {bl}"] = _query_bl(lookup, f"{domain}.{bl}", fn)
    for ip in _sending_ips(lookup, domain):
        rev = ".".join(reversed(ip.split(".")))
        for bl, fn in IP_BLS.items():
            results[f"{ip} @ {bl}"] = _query_bl(lookup, f"{rev}.{bl}", fn)

    details = {"results": {k: (f"{v[0]}: {v[1]}" if v[1] else v[0]) for k, v in results.items()}}
    listed = [f"{k} ({v[1]})" for k, v in results.items() if v[0] == "listed"]
    caution = [f"{k} ({v[1]})" for k, v in results.items() if v[0] == "caution"]
    answered = [k for k, v in results.items() if v[0] in ("clean", "listed", "caution", "ignore")]
    if listed:
        return CheckResult(
            "Blacklists", FAIL, f"Listed on {len(listed)} blocklist(s): {'; '.join(listed)}.",
            fix="Pause sending from this domain, find the cause (bad lists, spam complaints, a hacked "
                "mailbox), then request removal on each blocklist's website.",
            details=details,
        )
    if not answered:
        return CheckResult(
            "Blacklists", UNKNOWN,
            "Blocklists refused to answer. Spamhaus and URIBL block big public resolvers like 8.8.8.8.",
            fix="Run inboxready from a network that uses its own DNS resolver, or point --nameserver at one "
                "(see 'Getting real blocklist results' in the README).",
            details=details,
        )
    if caution:
        return CheckResult(
            "Blacklists", WARN, f"Not blocked, but flagged: {'; '.join(caution)}.",
            fix="Not a block on its own. Keep complaint rates low, and avoid putting this domain's links "
                "in cold emails.",
            details=details,
        )
    return CheckResult("Blacklists", PASS, f"Clean on {len(answered)} blocklist checks.", details=details)


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


# ---------------------------------------------------------------- Mailbox setup (provider-aware)

def check_mailbox_setup(mx: CheckResult, spf: CheckResult, dkim: CheckResult) -> CheckResult:
    """Is the domain's own mailbox provider actually authorised by SPF and signing with DKIM?"""
    provider = (mx.details or {}).get("provider")
    setup = providers.SETUP.get(provider or "")
    if not setup:
        msg = f"Mailboxes are on {provider}; no provider-specific checks for it yet." if provider \
            else "Mailbox provider not recognised, so provider-specific checks were skipped."
        return CheckResult("Setup", INFO, msg, details={"provider": provider})

    problems: List[str] = []
    fixes: List[str] = []
    includes = (spf.details or {}).get("includes") or []
    spf_record = (spf.details or {}).get("record")
    if spf_record and not providers.spf_authorizes(provider, includes):
        problems.append(f"SPF does not authorise {provider}")
        fixes.append(f"add include:{setup['spf_include']} to your SPF record")
    keys = (dkim.details or {}).get("keys") or []
    signing = {k["selector"] for k in keys if not k.get("revoked") and not k.get("broken")}
    if not signing.intersection(setup["selectors"]):
        problems.append(f"no {provider} DKIM key ({' or '.join(setup['selectors'])})")
        fixes.append(setup["dkim_steps"])

    details = {"provider": provider}
    if not problems:
        return CheckResult("Setup", PASS, f"Mailboxes on {provider}: SPF and DKIM are set up for it.",
                           details=details)
    if len(problems) == 2:
        status = FAIL
        impact = ("Mail sent from these mailboxes (including through Instantly, Smartlead or similar) "
                  "fails authentication, unless it is relayed through another server.")
    else:
        status = WARN
        impact = ("DMARC can still pass through the other method, but mail from these mailboxes "
                  "is only half authenticated.")
    hint = " (If you use a custom DKIM selector, pass --selector.)" if any("DKIM" in p for p in problems) else ""
    return CheckResult(
        "Setup", status,
        f"Mailboxes are on {provider}, but {' and '.join(problems)}. {impact}{hint}",
        fix=" Then ".join(f[0].upper() + f[1:] for f in fixes) + ".",
        details=details,
    )


# ---------------------------------------------------------------- Who can send as this domain (info)

def check_senders(spf: CheckResult, dkim: CheckResult, mx: CheckResult) -> CheckResult:
    names: List[str] = []
    unknown: List[str] = []
    for inc in (spf.details or {}).get("includes") or []:
        n = providers.sender_for_include(inc)
        if n:
            if n not in names:
                names.append(n)
        elif not any(inc.endswith(x) for x in ("_spf.google.com",)):
            unknown.append(inc)
    for k in (dkim.details or {}).get("keys") or []:
        n = providers.SENDER_BY_SELECTOR.get(k["selector"])
        if n and n not in names:
            names.append(n)
    details = {"services": names, "unrecognised_includes": unknown}
    if not names and not unknown:
        return CheckResult("Senders", INFO, "No sending services detected.", details=details)
    extra = f" plus {len(unknown)} unrecognised include(s)" if unknown else ""
    note = ""
    if len(names) >= 4:
        note = " These all share this domain's reputation; keep cold email on separate domains."
    return CheckResult("Senders", INFO, f"Can send as you: {', '.join(names) or 'none recognised'}{extra}.{note}",
                       details=details)


# ---------------------------------------------------------------- Domain age (RDAP)

def check_domain_age(domain: str, fetch, now: Optional[datetime] = None) -> CheckResult:
    now = now or datetime.now(timezone.utc)
    try:
        registered, created, expires = rdap.registration_dates(domain, fetch)
    except rdap.RdapUnavailable as exc:
        return CheckResult("Domain age", UNKNOWN, f"Couldn't fetch registration data ({exc}).")
    if not registered or not created:
        return CheckResult("Domain age", UNKNOWN, "Registry doesn't publish a registration date for this domain.")
    age = (now - created).days
    details = {"registered_domain": registered, "created": created.date().isoformat(), "age_days": age}
    if expires:
        details["expires"] = expires.date().isoformat()
    days_left = (expires - now).days if expires else None
    if days_left is not None and days_left < 0:
        return CheckResult("Domain age", FAIL, f"Domain registration expired {-days_left} days ago.",
                           fix="Renew it now at your registrar, or replies and DNS will stop working.",
                           details=details)
    if age < 14:
        return CheckResult(
            "Domain age", FAIL, f"Domain is only {age} days old. Brand-new domains sending cold email "
            "get filtered hard.",
            fix="Warm up the mailboxes for 2 to 4 weeks (low volume, real conversations) before any cold "
                "campaign from this domain.",
            details=details,
        )
    if age < 30:
        return CheckResult(
            "Domain age", WARN, f"Domain is {age} days old. Still young for cold email.",
            fix="Keep volume low (about 10 to 20 emails per mailbox per day) and keep warming up until it "
                "is at least a month old.",
            details=details,
        )
    if days_left is not None and days_left < 30:
        return CheckResult("Domain age", WARN, f"Domain expires in {days_left} days.",
                           fix="Renew it, or turn on auto-renew at your registrar.", details=details)
    years = age / 365.25
    when = f"{years:.1f} years" if years >= 1 else f"{age // 30} months"
    renew = f", renews in {days_left} days" if days_left is not None else ""
    return CheckResult("Domain age", PASS, f"Registered {when} ago{renew}.", details=details)
