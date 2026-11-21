import pytest

from inboxready import checks
from inboxready.dnsutil import LookupFailed, parse_doh_answer
from inboxready.report import normalize_domain, run, score_results

from pathlib import Path

# Public keys generated with openssl (no private keys are stored).
KEYS = Path(__file__).parent / "keys"
KEY_2048 = (KEYS / "rsa2048.txt").read_text().strip()
KEY_1024 = (KEYS / "rsa1024.txt").read_text().strip()
KEY_2048_PKCS1 = (KEYS / "rsa2048_pkcs1.txt").read_text().strip()
KEY_512 = (KEYS / "rsa512.txt").read_text().strip()
# Real record seen at pm._domainkey.shopify.com: the key is cut off part-way through.
KEY_TRUNCATED = ("MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhANOtTzK6Ct6R4u976UZjFs1eiurj69J8l0P0LfRJnRCB/"
                 "ReBQk6aZVVi2hQ82Q9Dt0rAW61ejGe4bAFx")


def fake(records):
    """records: {(name, rtype): [values]}; ("fail", name) raises LookupFailed."""

    def lookup(name, rtype):
        if ("fail", name) in records:
            raise LookupFailed("timeout")
        return list(records.get((name.lower(), rtype), []))

    return lookup


GOOD = {
    ("good.com", "TXT"): ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"],
    ("_spf.google.com", "TXT"): ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"],
    ("_netblocks.google.com", "TXT"): ["v=spf1 ip4:35.190.247.0/24 ~all"],
    ("_netblocks2.google.com", "TXT"): ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
    ("_dmarc.good.com", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:d@good.com"],
    ("google._domainkey.good.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_2048}"],
    ("good.com", "MX"): ["1 aspmx.l.google.com", "5 alt1.aspmx.l.google.com"],
    ("aspmx.l.google.com", "A"): ["142.250.1.27"],
    ("alt1.aspmx.l.google.com", "A"): ["142.250.2.27"],
    ("good.com", "A"): ["93.184.216.34"],
    ("good.com", "SOA"): ["ns1.good.com. admin.good.com. 1 2 3 4 5"],
}


# ---------------------------------------------------------------- SPF

def test_spf_pass_counts_nested_includes():
    r = checks.check_spf(fake(GOOD), "good.com")
    assert r.status == "pass"
    assert r.details["dns_lookups"] == 3


def test_spf_missing():
    assert checks.check_spf(fake({}), "x.com").status == "fail"


def test_spf_multiple_records_is_fail():
    r = checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 -all", "v=spf1 mx -all"]}), "x.com")
    assert r.status == "fail" and "2 SPF" in r.summary


def test_spf_plus_all_is_fail():
    r = checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 +all"]}), "x.com")
    assert r.status == "fail"


def test_spf_bare_all_is_fail():
    r = checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 ip4:1.2.3.4 all"]}), "x.com")
    assert r.status == "fail"


def test_spf_neutral_and_missing_all_warn():
    assert checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 mx ?all"]}), "x.com").status == "warn"
    assert checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 mx"]}), "x.com").status == "warn"


def test_spf_redirect_without_all_is_ok():
    recs = {("x.com", "TXT"): ["v=spf1 redirect=_spf.x.com"], ("_spf.x.com", "TXT"): ["v=spf1 ip4:1.1.1.1 -all"]}
    assert checks.check_spf(fake(recs), "x.com").status == "pass"


def test_spf_over_ten_lookups_fails():
    recs = {("x.com", "TXT"): ["v=spf1 " + " ".join(f"include:i{n}.com" for n in range(11)) + " ~all"]}
    for n in range(11):
        recs[(f"i{n}.com", "TXT")] = ["v=spf1 ip4:1.1.1.1 ~all"]
    r = checks.check_spf(fake(recs), "x.com")
    assert r.status == "fail" and r.details["dns_lookups"] == 11


def test_spf_include_loop_is_error_and_terminates():
    recs = {("a.com", "TXT"): ["v=spf1 include:b.com ~all"], ("b.com", "TXT"): ["v=spf1 include:a.com ~all"]}
    r = checks.check_spf(fake(recs), "a.com")
    assert r.status == "fail" and "loop" in r.summary


def test_spf_near_limit_warns():
    recs = {("x.com", "TXT"): ["v=spf1 a mx " + " ".join(f"include:i{n}.com" for n in range(6)) + " ~all"]}
    for n in range(6):
        recs[(f"i{n}.com", "TXT")] = ["v=spf1 ip4:1.1.1.1 ~all"]
    assert checks.check_spf(fake(recs), "x.com").status == "warn"


def test_spf_dns_failure_is_unknown():
    assert checks.check_spf(fake({("fail", "x.com"): True}), "x.com").status == "unknown"


# ---------------------------------------------------------------- DMARC

@pytest.mark.parametrize("record,status", [
    ("v=DMARC1; p=reject; rua=mailto:a@x.com", "pass"),
    ("v=DMARC1; p=quarantine; rua=mailto:a@x.com", "pass"),
    ("v=DMARC1; p=none; rua=mailto:a@x.com", "warn"),
    ("v=DMARC1; p=reject; pct=50; rua=mailto:a@x.com", "warn"),
    ("v=DMARC1; p=reject", "warn"),
    ("v=DMARC1; rua=mailto:a@x.com", "fail"),
])
def test_dmarc_policies(record, status):
    assert checks.check_dmarc(fake({("_dmarc.x.com", "TXT"): [record]}), "x.com").status == status


def test_dmarc_missing():
    assert checks.check_dmarc(fake({}), "x.com").status == "fail"


def test_dmarc_subdomain_inherits_org_policy():
    recs = {("_dmarc.x.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@x.com"]}
    r = checks.check_dmarc(fake(recs), "mail.x.com")
    assert r.status == "pass" and r.details["inherited_from"] == "x.com"


def test_dmarc_tree_walk_co_uk():
    recs = {("_dmarc.shop.co.uk", "TXT"): ["v=DMARC1; p=reject; rua=mailto:a@shop.co.uk"]}
    r = checks.check_dmarc(fake(recs), "mail.eu.shop.co.uk")
    assert r.status == "pass" and r.details["inherited_from"] == "shop.co.uk"


def test_dmarc_subdomain_uses_sp():
    recs = {("_dmarc.x.com", "TXT"): ["v=DMARC1; p=reject; sp=none; rua=mailto:a@x.com"]}
    r = checks.check_dmarc(fake(recs), "send.x.com")
    assert r.status == "warn" and "sp=none" in r.summary
    assert checks.check_dmarc(fake(recs), "x.com").status == "pass"


def test_dmarc_ignores_non_dmarc_txt_and_never_queries_tld():
    asked = []

    def lookup(name, rtype):
        asked.append(name)
        return ["v=DMARC10; p=reject"] if name == "_dmarc.x.com" else []

    assert checks.check_dmarc(lookup, "a.x.com").status == "fail"
    assert "_dmarc.com" not in asked


# ---------------------------------------------------------------- SPF syntax

@pytest.mark.parametrize("term,ok", [
    ("ip4:192.0.2.0/24", True), ("ip6:2001:db8::/32", True), ("-all", True), ("~all", True),
    ("include:_spf.google.com", True), ("a", True), ("a:mail.x.com/24", True), ("mx/24//64", True),
    ("exp=explain.x.com", True), ("redirect=_spf.x.com", True), ("custom-mod=val", True),
    ("ip4:999.1.1.1", False), ("ip4:2001:db8::1", False), ("ip6:10.0.0.1", False), ("inclde:x.com", False),
    ("include:", False), ("all:x.com", False), ("a/33", False), ("ptr/24", False), ("ip4", False),
])
def test_spf_term_syntax(term, ok):
    assert (checks._spf_term_error(term) is None) == ok


def test_spf_typo_is_fail():
    r = checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 inclde:_spf.google.com ~all"]}), "x.com")
    assert r.status == "fail" and "inclde" in r.summary


def test_spf_include_without_record_is_fail():
    r = checks.check_spf(fake({("x.com", "TXT"): ["v=spf1 include:gone.example ~all"]}), "x.com")
    assert r.status == "fail" and "gone.example" in r.summary


def test_spf_ignores_spf10_lookalike():
    assert checks.check_spf(fake({("x.com", "TXT"): ["v=spf10 -all"]}), "x.com").status == "fail"
    assert "No SPF" in checks.check_spf(fake({("x.com", "TXT"): ["v=spf10 -all"]}), "x.com").summary


def test_spf_redirect_ignored_when_all_present():
    recs = {("x.com", "TXT"): ["v=spf1 mx redirect=_spf.x.com -all"]}
    r = checks.check_spf(fake(recs), "x.com")
    assert r.status == "pass" and r.details["dns_lookups"] == 1


def test_spf_too_many_void_lookups():
    recs = {("x.com", "TXT"): ["v=spf1 include:v1.com include:v2.com include:v3.com ~all"]}
    assert checks.check_spf(fake(recs), "x.com").status == "fail"


# ---------------------------------------------------------------- DKIM extras

def test_dkim_wildcard_detected():
    def lookup(name, rtype):
        return [f"v=DKIM1; k=rsa; p={KEY_2048}"] if name.endswith("._domainkey.w.com") else []

    r = checks.check_dkim(lookup, "w.com")
    assert r.status == "unknown" and "wildcard" in r.summary


def test_dkim_wildcard_null_key_means_never_signs():
    def lookup(name, rtype):
        return ["v=DKIM1; p="] if name.endswith("._domainkey.example.com") else []

    r = checks.check_dkim(lookup, "example.com")
    assert r.status == "fail" and "never signs" in r.summary


def test_dkim_ignores_spf_wildcard_txt():
    def lookup(name, rtype):
        return ["v=spf1 include:x.com ~all"] if name.endswith("._domainkey.w.com") else []

    assert checks.check_dkim(lookup, "w.com").status == "warn"


# ---------------------------------------------------------------- DKIM

def test_dkim_found_2048():
    r = checks.check_dkim(fake(GOOD), "good.com")
    assert r.status == "pass" and r.details["keys"][0]["bits"] == 2048


def test_dkim_1024_passes_with_tip():
    recs = {("s1._domainkey.x.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_1024}"]}
    r = checks.check_dkim(fake(recs), "x.com")
    assert r.status == "pass" and "2048-bit is recommended" in r.summary


def test_dkim_under_1024_warns():
    recs = {("s1._domainkey.x.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_512}"],
            ("google._domainkey.x.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_2048}"]}
    r = checks.check_dkim(fake(recs), "x.com")
    assert r.status == "warn" and "s1 (512-bit, too weak)" in r.summary


def test_dkim_truncated_key_detected():
    assert checks._rsa_bits(KEY_TRUNCATED) is None
    only_broken = {("pm._domainkey.x.com", "TXT"): [f"v=DKIM1; k=rsa; p={KEY_TRUNCATED}"]}
    assert checks.check_dkim(fake(only_broken), "x.com").status == "fail"
    mixed = dict(only_broken)
    mixed[("google._domainkey.x.com", "TXT")] = [f"v=DKIM1; k=rsa; p={KEY_2048}"]
    r = checks.check_dkim(fake(mixed), "x.com")
    assert r.status == "warn" and "pm (broken key)" in r.summary


def test_dkim_not_found_common_is_warn_custom_is_fail():
    assert checks.check_dkim(fake({}), "x.com").status == "warn"
    assert checks.check_dkim(fake({}), "x.com", ["custom"]).status == "fail"


def test_dkim_revoked_key_not_counted():
    recs = {("s1._domainkey.x.com", "TXT"): ["v=DKIM1; p="]}
    assert checks.check_dkim(fake(recs), "x.com").status == "warn"


def test_dkim_pkcs1_key_size():
    assert checks._rsa_bits(KEY_2048_PKCS1) == 2048
    assert checks._rsa_bits("not-base64!!") is None


def test_dkim_ed25519():
    recs = {("s1._domainkey.x.com", "TXT"): ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="]}
    assert checks.check_dkim(fake(recs), "x.com").status == "pass"


# ---------------------------------------------------------------- MX / website / blacklists

def test_mx_provider_detection():
    r = checks.check_mx(fake(GOOD), "good.com")
    assert r.status == "pass" and r.details["provider"] == "Google Workspace"


def test_mx_missing_and_null():
    assert checks.check_mx(fake({}), "x.com").status == "fail"
    assert checks.check_mx(fake({("x.com", "MX"): ["0 "]}), "x.com").status == "fail"


def test_website():
    assert checks.check_website(fake(GOOD), "good.com").status == "pass"
    assert checks.check_website(fake({}), "x.com").status == "warn"


def test_blacklist_clean():
    assert checks.check_blacklists(fake(GOOD), "good.com").status == "pass"


def test_blacklist_listed():
    recs = dict(GOOD)
    recs[("good.com.dbl.spamhaus.org", "A")] = ["127.0.1.2"]
    r = checks.check_blacklists(fake(recs), "good.com")
    assert r.status == "fail" and "dbl.spamhaus.org" in r.summary


def test_blacklist_refused_queries_are_unknown_not_listed():
    recs = {("x.com.dbl.spamhaus.org", "A"): ["127.255.255.254"],
            ("x.com.multi.uribl.com", "A"): ["127.0.0.1"],
            ("x.com.multi.surbl.org", "A"): ["127.0.0.1"]}
    assert checks.check_blacklists(fake(recs), "x.com").status == "unknown"


# ---------------------------------------------------------------- report

def test_full_report_good_domain_scores_a():
    rep = run("good.com", fake(GOOD))
    assert rep.score == 100 and rep.grade == "A"


def test_missing_domain_reported_clearly():
    rep = run("nope-not-real.com", fake({}))
    assert rep.results[0].name == "Domain" and rep.grade == "F"


def test_unknown_checks_dont_hurt_score():
    rs = [checks.CheckResult("SPF", "pass", ""), checks.CheckResult("Blacklists", "unknown", "")]
    assert score_results(rs) == 100


@pytest.mark.parametrize("raw,expected", [
    ("Example.com", "example.com"),
    ("https://www.example.com/path", "example.com"),
    ("ajay@example.co.uk", "example.co.uk"),
    ("example.com.", "example.com"),
])
def test_normalize(raw, expected):
    assert normalize_domain(raw) == expected


def test_normalize_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_domain("not a domain")


# ---------------------------------------------------------------- DoH parsing

def test_parse_doh_txt_chunks_and_types():
    payload = {"Status": 0, "Answer": [
        {"type": 5, "data": "alias.example.com."},
        {"type": 16, "data": '"v=spf1 include:a.com " "~all"'},
        {"type": 16, "data": "v=DMARC1; p=none"},
    ]}
    assert parse_doh_answer(payload, "TXT") == ["v=spf1 include:a.com ~all", "v=DMARC1; p=none"]


def test_parse_doh_mx_and_nxdomain():
    assert parse_doh_answer({"Status": 0, "Answer": [{"type": 15, "data": "10 mx.a.com."}]}, "MX") == ["10 mx.a.com"]
    assert parse_doh_answer({"Status": 3}, "A") == []
    with pytest.raises(LookupFailed):
        parse_doh_answer({"Status": 2}, "A")


def test_normalize_idn():
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"


def test_dkim_key_with_whitespace():
    spaced = " ".join(KEY_2048[i:i + 60] for i in range(0, len(KEY_2048), 60))
    assert checks._rsa_bits(spaced) == 2048


def test_doh_lookup_parses_http_response(monkeypatch):
    import io
    import json as _json

    from inboxready import dnsutil

    body = _json.dumps({"Status": 0, "Answer": [{"type": 16, "data": '"v=spf1 -all"'}]}).encode()
    monkeypatch.setattr(dnsutil.urllib.request, "urlopen", lambda req, timeout: io.BytesIO(body))
    assert dnsutil.make_doh_lookup()("x.com", "TXT") == ["v=spf1 -all"]
