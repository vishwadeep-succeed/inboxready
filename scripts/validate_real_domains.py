"""Cross-check inboxready against checkdmarc on real domains (run in CI with live DNS).

Prints one line per domain and a MISMATCH line for every disagreement.
"""

import sys
import time

import checkdmarc

import inboxready

DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "salesforce.com",
    "hubspot.com", "mailchimp.com", "sendgrid.com", "instantly.ai", "apollo.io", "lemlist.com",
    "smartlead.ai", "stripe.com", "shopify.com", "notion.so", "slack.com", "zoom.us",
    "atlassian.com", "dropbox.com", "paypal.com", "linkedin.com", "bbc.co.uk", "gov.uk",
    "zoho.com", "freshworks.com", "infosys.com", "succeedlearn.com", "succeedtech.com",
    "elearnposh.com", "example.com", "mail.google.com", "this-domain-does-not-exist-9x7q.com",
]


def ours(domain):
    t = time.time()
    rep = inboxready.check(domain)
    by = {r.name: r for r in rep.results}
    spf = by.get("SPF")
    dmarc = by.get("DMARC")
    mx = by.get("MX")
    return {
        "time": time.time() - t,
        "score": rep.score,
        "grade": rep.grade,
        "exists": "Domain" not in by,
        "spf_record": (spf.details or {}).get("record") if spf else None,
        "spf_lookups": (spf.details or {}).get("dns_lookups") if spf else None,
        "spf_invalid": bool(spf and (spf.details or {}).get("errors")) or bool(spf and "limit is 10" in spf.summary),
        "dmarc_record": (dmarc.details or {}).get("record") if dmarc else None,
        "dmarc_p": ((dmarc.details or {}).get("record") or "") if dmarc else "",
        "has_mx": bool(mx and mx.status == "pass"),
        "statuses": {r.name: r.status for r in rep.results},
        "summaries": {r.name: r.summary for r in rep.results},
    }


def theirs(domain):
    r = checkdmarc.check_domains([domain])
    if isinstance(r, list):
        r = r[0]
    spf = r.get("spf", {}) or {}
    dmarc = r.get("dmarc", {}) or {}
    mx = r.get("mx", {}) or {}
    p = None
    tags = dmarc.get("tags") or {}
    if isinstance(tags.get("p"), dict):
        p = tags["p"].get("value")
    return {
        "spf_record": spf.get("record"),
        "spf_valid": spf.get("valid"),
        "spf_lookups": spf.get("dns_lookups"),
        "spf_error": spf.get("error"),
        "dmarc_record": dmarc.get("record"),
        "dmarc_location": dmarc.get("location"),
        "dmarc_p": p,
        "dmarc_error": dmarc.get("error"),
        "has_mx": bool(mx.get("hosts")),
    }


def tag_p(record):
    for part in (record or "").split(";"):
        k, _, v = part.partition("=")
        if k.strip().lower() == "p":
            return v.strip().lower()
    return None


mismatches = 0
for d in DOMAINS:
    try:
        a = ours(d)
    except Exception as exc:  # noqa: BLE001
        print(f"MISMATCH {d}: inboxready crashed: {exc!r}")
        mismatches += 1
        continue
    try:
        b = theirs(d)
    except Exception as exc:  # noqa: BLE001
        b = None
        print(f"note {d}: checkdmarc failed: {exc!r}")

    print(f"\n== {d}  {a['score']}/100 {a['grade']}  ({a['time']:.1f}s)")
    for name, st in a["statuses"].items():
        print(f"   {st:<8}{name:<11}{a['summaries'][name]}")
    if b is None or not a["exists"]:
        continue

    def mm(what, x, y):
        global mismatches
        mismatches += 1
        print(f"MISMATCH {d} {what}: inboxready={x!r} checkdmarc={y!r}")

    if bool(a["spf_record"]) != bool(b["spf_record"]):
        mm("spf_present", a["spf_record"], b["spf_record"] or b["spf_error"])
    elif a["spf_record"]:
        if b["spf_lookups"] is not None and a["spf_lookups"] != b["spf_lookups"]:
            mm("spf_lookups", a["spf_lookups"], b["spf_lookups"])
        if b["spf_valid"] is not None and a["spf_invalid"] == bool(b["spf_valid"]):
            mm("spf_valid", not a["spf_invalid"], b["spf_valid"])
    if bool(a["dmarc_record"]) != bool(b["dmarc_record"]):
        mm("dmarc_present", a["dmarc_record"], b["dmarc_record"] or b["dmarc_error"])
    elif a["dmarc_record"] and b["dmarc_p"] and tag_p(a["dmarc_record"]) != b["dmarc_p"]:
        mm("dmarc_p", tag_p(a["dmarc_record"]), b["dmarc_p"])
    if a["has_mx"] != b["has_mx"]:
        mm("mx", a["has_mx"], b["has_mx"])

print(f"\nTOTAL MISMATCHES: {mismatches}")
sys.exit(0)
