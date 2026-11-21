"""Tests for the cold-email-specific features: provider setup, senders, domain age, fixes, snapshots."""

import json
from datetime import datetime, timedelta, timezone

from inboxready import checks, cli, compare, fixes
from inboxready.report import run
from tests.test_checks import GOOD, KEY_2048, fake

NOW = datetime(2026, 11, 21, tzinfo=timezone.utc)


def rdap_for(created_days_ago=None, expires_in=None, only=None):
    def fetch(domain):
        if only and domain != only:
            return None
        events = []
        if created_days_ago is not None:
            events.append({"eventAction": "registration",
                           "eventDate": (NOW - timedelta(days=created_days_ago)).isoformat()})
        if expires_in is not None:
            events.append({"eventAction": "expiration",
                           "eventDate": (NOW + timedelta(days=expires_in)).isoformat()})
        return {"events": events}
    return fetch


def results_for(recs, domain):
    rep = run(domain, fake(recs), domain_age=False)
    return {r.name: r for r in rep.results}, rep


# ---------------------------------------------------------------- Setup (provider-aware)

def test_setup_pass_for_complete_google_domain():
    by, _ = results_for(GOOD, "good.com")
    assert by["Setup"].status == "pass" and "Google Workspace" in by["Setup"].summary


def test_setup_catches_google_mailboxes_missing_from_spf():
    recs = dict(GOOD)
    recs[("good.com", "TXT")] = ["v=spf1 include:sendgrid.net ~all"]
    recs[("sendgrid.net", "TXT")] = ["v=spf1 ip4:167.89.0.0/17 ~all"]
    by, _ = results_for(recs, "good.com")
    st = by["Setup"]
    assert st.status == "warn" and "SPF does not authorise Google Workspace" in st.summary
    assert st.dns_fixes[0]["value"] == "v=spf1 include:sendgrid.net include:_spf.google.com ~all"


def test_setup_follows_nested_includes():
    recs = dict(GOOD)
    recs[("good.com", "TXT")] = ["v=spf1 include:_spf.good.com -all"]
    recs[("_spf.good.com", "TXT")] = ["v=spf1 include:_spf.google.com ~all"]
    by, _ = results_for(recs, "good.com")
    assert by["Setup"].status == "pass"


def test_setup_microsoft_without_dkim():
    recs = {
        ("ms.com", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all"],
        ("spf.protection.outlook.com", "TXT"): ["v=spf1 ip4:40.92.0.0/15 -all"],
        ("ms.com", "MX"): ["0 ms-com.mail.protection.outlook.com"],
        ("ms.com", "A"): ["1.2.3.4"],
    }
    by, _ = results_for(recs, "ms.com")
    st = by["Setup"]
    assert st.status == "warn" and "selector1 or selector2" in st.summary and "Defender" in st.fix


def test_setup_fails_when_both_spf_and_dkim_missing():
    recs = {k: v for k, v in GOOD.items() if not k[0].startswith("google._domainkey")}
    recs[("good.com", "TXT")] = ["v=spf1 ip4:203.0.113.0/24 -all"]
    by, _ = results_for(recs, "good.com")
    assert by["Setup"].status == "fail" and "relayed" in by["Setup"].summary


def test_setup_unknown_provider_is_info():
    recs = {("x.com", "MX"): ["10 mail.x.com"], ("x.com", "A"): ["1.2.3.4"]}
    by, _ = results_for(recs, "x.com")
    assert by["Setup"].status == "info"


# ---------------------------------------------------------------- Senders

def test_senders_lists_services_from_spf_and_dkim():
    recs = dict(GOOD)
    recs[("good.com", "TXT")] = ["v=spf1 include:_spf.google.com include:sendgrid.net include:x.hubspotemail.net ~all"]
    recs[("sendgrid.net", "TXT")] = ["v=spf1 ip4:1.1.1.1 ~all"]
    recs[("x.hubspotemail.net", "TXT")] = ["v=spf1 ip4:2.2.2.2 ~all"]
    recs[("k1._domainkey.good.com", "TXT")] = [f"v=DKIM1; k=rsa; p={KEY_2048}"]
    by, _ = results_for(recs, "good.com")
    services = by["Senders"].details["services"]
    assert services == ["Google Workspace", "SendGrid", "HubSpot", "Mailchimp"]
    assert "separate domains" in by["Senders"].summary


# ---------------------------------------------------------------- Domain age

def test_domain_age_new_domain_fails():
    r = checks.check_domain_age("new.com", rdap_for(5, 360), now=NOW)
    assert r.status == "fail" and "5 days old" in r.summary


def test_domain_age_young_warns_and_old_passes():
    assert checks.check_domain_age("y.com", rdap_for(20, 340), now=NOW).status == "warn"
    r = checks.check_domain_age("o.com", rdap_for(1200, 200), now=NOW)
    assert r.status == "pass" and "3.3 years" in r.summary


def test_domain_age_expiring_and_expired():
    assert "expires in 10 days" in checks.check_domain_age("e.com", rdap_for(900, 10), now=NOW).summary
    assert checks.check_domain_age("x.com", rdap_for(900, -3), now=NOW).status == "fail"


def test_domain_age_walks_up_from_subdomain():
    r = checks.check_domain_age("send.acme.com", rdap_for(800, 100, only="acme.com"), now=NOW)
    assert r.status == "pass" and r.details["registered_domain"] == "acme.com"


def test_domain_age_unavailable_is_unknown_and_not_scored():
    r = checks.check_domain_age("x.com", lambda d: (_ for _ in ()).throw(checks.rdap.RdapUnavailable("down")), now=NOW)
    assert r.status == "unknown"
    rep = run("good.com", fake(GOOD))  # conftest makes RDAP unavailable
    assert rep.score == 100


# ---------------------------------------------------------------- Fix planner

def test_fix_missing_spf_and_dmarc_for_google_domain():
    recs = {("g.com", "MX"): ["1 smtp.google.com"], ("g.com", "A"): ["1.2.3.4"]}
    by, _ = results_for(recs, "g.com")
    assert by["SPF"].dns_fixes[0]["value"] == "v=spf1 include:_spf.google.com ~all"
    d = by["DMARC"].dns_fixes[0]
    assert d["host"] == "_dmarc.g.com" and d["value"].startswith("v=DMARC1; p=none; rua=mailto:dmarc@g.com")


def test_fix_merges_multiple_spf_records():
    merged = fixes.merge_spf(["v=spf1 include:_spf.google.com ~all", "v=spf1 include:sendgrid.net -all"])
    assert merged == "v=spf1 include:_spf.google.com include:sendgrid.net ~all"


def test_fix_dmarc_next_step_keeps_other_tags():
    recs = dict(GOOD)
    recs[("_dmarc.good.com", "TXT")] = ["v=DMARC1; p=none; rua=mailto:d@good.com; adkim=s"]
    by, _ = results_for(recs, "good.com")
    assert by["DMARC"].dns_fixes[0]["value"] == "v=DMARC1; p=quarantine; rua=mailto:d@good.com; adkim=s"


def test_fix_plus_all_replaced():
    recs = dict(GOOD)
    recs[("good.com", "TXT")] = ["v=spf1 include:_spf.google.com +all"]
    by, _ = results_for(recs, "good.com")
    assert by["SPF"].dns_fixes[0]["value"] == "v=spf1 include:_spf.google.com ~all"


def test_fix_no_mx_suggests_provider_mx_from_spf():
    recs = {("g.com", "TXT"): ["v=spf1 include:_spf.google.com ~all"], ("g.com", "A"): ["1.2.3.4"]}
    recs.update({k: v for k, v in GOOD.items() if k[0].endswith("google.com")})
    by, _ = results_for(recs, "g.com")
    assert by["MX"].dns_fixes == [{"action": "add", "type": "MX", "host": "g.com",
                                   "value": "1 smtp.google.com", "note": "Google Workspace mail server"}]


def test_add_include_variants():
    assert fixes.add_include("v=spf1 mx -all", "a.com") == "v=spf1 mx include:a.com -all"
    assert fixes.add_include("v=spf1 redirect=x.com", "a.com") == "v=spf1 include:a.com redirect=x.com"
    assert fixes.add_include("v=spf1 mx", "a.com") == "v=spf1 mx include:a.com ~all"
    assert fixes.add_include("v=spf1 include:a.com -all", "a.com") == "v=spf1 include:a.com -all"


# ---------------------------------------------------------------- Blocklist codes

def test_blocklist_abused_and_grey_are_warnings_not_failures():
    recs = dict(GOOD)
    recs[("good.com.dbl.spamhaus.org", "A")] = ["127.0.1.102"]
    recs[("good.com.multi.uribl.com", "A")] = ["127.0.0.4"]
    r = checks.check_blacklists(fake(recs), "good.com")
    assert r.status == "warn" and "abused" in r.summary and "grey" in r.summary


def test_blocklist_pbl_ignored_and_only_spf_ips_checked():
    recs = dict(GOOD)
    recs[("good.com", "TXT")] = ["v=spf1 ip4:203.0.113.7 include:_spf.google.com ~all"]
    recs[("7.113.0.203.zen.spamhaus.org", "A")] = ["127.0.0.11"]
    r = checks.check_blacklists(fake(recs), "good.com")
    assert r.status == "pass"
    assert not any("142.250" in k for k in r.details["results"])  # MX IPs are not sending IPs
    recs[("7.113.0.203.zen.spamhaus.org", "A")] = ["127.0.0.2"]
    assert checks.check_blacklists(fake(recs), "good.com").status == "fail"


def test_blocklist_public_resolver_refusal_is_unknown():
    recs = {("x.com.dbl.spamhaus.org", "A"): ["127.255.255.254"],
            ("x.com.multi.uribl.com", "A"): ["127.0.0.1"],
            ("x.com.multi.surbl.org", "A"): ["127.0.0.1"]}
    assert checks.check_blacklists(fake(recs), "x.com").status == "unknown"


# ---------------------------------------------------------------- Snapshots and fleet view

def _cli(monkeypatch, capsys, recs, argv):
    monkeypatch.setattr(cli, "make_lookup", lambda ns=None: fake(recs))
    code = cli.main(argv)
    return code, capsys.readouterr().out


def test_save_and_compare_detects_breakage(monkeypatch, capsys, tmp_path):
    snap = tmp_path / "snap.json"
    code, _ = _cli(monkeypatch, capsys, GOOD, ["good.com", "--save", str(snap), "--no-age"])
    assert code == 0 and json.loads(snap.read_text())[0]["domain"] == "good.com"

    broken = dict(GOOD)
    broken[("good.com", "TXT")] = ["v=spf1 include:_spf.google.com +all"]
    code, out = _cli(monkeypatch, capsys, broken, ["good.com", "--compare", str(snap), "--no-age"])
    assert code == 1 and "SPF got worse (pass -> fail)" in out


def test_compare_reports_silent_record_edits():
    old = {"x.com": {"DMARC": {"name": "DMARC", "status": "pass", "details": {"record": "v=DMARC1; p=reject"}}}}
    new = [{"domain": "x.com", "checks": [{"name": "DMARC", "status": "pass",
                                           "details": {"record": "v=DMARC1; p=reject; rua=mailto:a@x.com"}}]}]
    lines, worse = compare.diff(old, new)
    assert not worse and "DMARC record changed" in lines[0]


def test_fleet_summary_and_fix_output(monkeypatch, capsys):
    recs = dict(GOOD)
    recs[("bad.com", "A")] = ["1.2.3.4"]
    recs[("bad.com", "MX")] = ["1 smtp.google.com"]
    code, out = _cli(monkeypatch, capsys, recs, ["good.com", "bad.com", "--fix", "--no-age"])
    assert "Fleet summary: 1 of 2 domains ready to send" in out
    fleet = out[out.index("Fleet summary"):]
    assert fleet.index("bad.com") < fleet.index("good.com")  # worst first
    assert "DNS changes to make:" in out and "Value: v=spf1 include:_spf.google.com ~all" in out
