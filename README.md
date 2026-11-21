# inboxready

[![CI](https://github.com/vishwadeep-succeed/inboxready/actions/workflows/ci.yml/badge.svg)](https://github.com/vishwadeep-succeed/inboxready/actions/workflows/ci.yml)

**Check every cold email sending domain in one command. Get the exact DNS fixes, and get told when something breaks.**

Most deliverability checkers look at one domain at a time and stop at "DKIM: fail". `inboxready` is built for how outbound teams actually work: a dozen or more secondary domains, mailboxes on Google Workspace or Microsoft 365, and a sending tool like Instantly or Smartlead on top. It checks the whole fleet, explains each problem in plain English, gives you the DNS record to paste, and can watch your domains so you hear about breakage before your reply rate drops.

```
$ inboxready acme-outreach.com --fix

  acme-outreach.com  74/100 (grade C)

  ✔ SPF        Valid SPF record (1/10 DNS lookups).
  ✔ DKIM       DKIM key found: google.
  ! DMARC      DMARC is p=none, monitoring only. It passes the Gmail/Yahoo rule but does not protect your domain from spoofing.
               Fix: Once SPF and DKIM pass in your reports, move to p=quarantine.
  ✔ MX         1 MX record(s), hosted on Google Workspace.
  ✘ Setup      Mailboxes are on Google Workspace, but SPF does not authorise Google Workspace. Mail sent from these mailboxes (including through Instantly, Smartlead or similar) can fail authentication.
               Fix: Add include:_spf.google.com to your SPF record.
  ✔ Blacklists Clean on 3 blocklist checks.
  ✔ Domain age Registered 2.1 years ago, renews in 140 days.
  ✔ Website    Domain resolves to a website.
  i Senders    Can send as you: SendGrid, Google Workspace.

  DNS changes to make:
    [Setup] REPLACE TXT record
      Host:  acme-outreach.com
      Value: v=spf1 include:sendgrid.net include:_spf.google.com ~all
      Note:  Your current SPF record with Google Workspace added.
```

## What makes it different

**It knows your mailbox provider.** It reads your MX records, works out whether your mailboxes are on Google Workspace, Microsoft 365 or Zoho, and checks that SPF and DKIM are set up *for that provider*. "SPF is valid but doesn't include Google" is the most common cold email setup mistake, and generic checkers pass it.

**It gives you the record, not just the problem.** `--fix` prints exactly what to paste into Cloudflare, GoDaddy or Namecheap: your current SPF record with the missing include merged in, several SPF records combined into one, or your DMARC record moved to the next policy with your other tags kept.

**It checks domain age.** A domain registered 9 days ago will get filtered no matter how perfect its DNS is. `inboxready` looks up the registration date (over RDAP, no API key needed) and tells you when a domain is too new for cold email, still warming up, or about to expire.

**It's built for many domains.** Pass a list, a text file or the CSV you exported from Instantly, Smartlead or Apollo. It finds the email or domain column on its own, dedupes, and ends with a fleet summary ranked worst first.

**It watches for breakage.** `--save` stores a snapshot. `--compare` shows what changed since then, including silent record edits, and exits with an error if anything got worse. Run it on a schedule in GitHub Actions (see below) and you get an email when someone breaks your SPF.

**It reads blocklist codes properly.** Spamhaus and URIBL return different codes for different things. `inboxready` separates a real listing from "legitimate domain whose links were abused", the URIBL grey list, the Spamhaus policy list, and "your DNS resolver was refused". A cruder checker reports all of those as "blacklisted".

**It catches broken records.** For example, it flags DKIM keys that were cut off when pasted into DNS, include typos like `inclde:`, invalid IP ranges, SPF include loops, and more than 10 DNS lookups.

## How it compares

| | inboxready | Web checkers (MXToolbox, etc.) | checkdmarc |
|---|---|---|---|
| Many domains at once, CSV and lead-export input | ✔ | One at a time | ✔ |
| Mailbox-provider-aware setup check | ✔ | ✘ | ✘ |
| Copy-paste DNS fixes | ✔ | Partial | ✘ |
| Domain age and expiry | ✔ | Separate tool | ✘ |
| Snapshot and change alerts | ✔ | Paid monitoring | ✘ |
| Free, open source, runs in CI | ✔ | ✘ | ✔ |

## Install

```bash
pip install inboxready
```

Needs Python 3.10+. The only dependency is `dnspython`. Works on Linux, macOS and Windows.

## Usage

```bash
inboxready yourdomain.com                      # one domain (an email address or URL works too)
inboxready getacme.com tryacme.com acmehq.com  # several, with a ranked fleet summary
inboxready -f leads_export.csv                 # a CSV: finds the email/domain/website column itself
inboxready -f domains.csv -c "Sending Domain"  # or name the column (or give its number)
inboxready yourdomain.com --fix                # print the exact DNS records to add or replace
inboxready -f domains.txt --csv > report.csv   # spreadsheet-friendly summary
inboxready yourdomain.com --json               # full details for scripts and dashboards
inboxready yourdomain.com --selector s2024     # your DKIM selector, if it isn't a common one
inboxready yourdomain.com --doh                # on networks that block normal DNS
```

### Watch your domains and get alerts

Save a snapshot once, then compare against it later:

```bash
inboxready -f domains.txt --save snapshot.json
inboxready -f domains.txt --compare snapshot.json
```

`--compare` lists every status change and record edit, and exits with code `1` if anything got worse.

For free scheduled monitoring, add this file to any GitHub repo as `.github/workflows/domains.yml`, with your domains in `domains.txt`. GitHub emails you when the run fails:

```yaml
name: Check sending domains
on:
  schedule:
    - cron: "0 6 * * *"   # every day at 06:00 UTC
  workflow_dispatch:
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - run: pip install inboxready
      - run: inboxready -f domains.txt --min-score 75
```

Exit codes: `0` all good, `1` a domain scored below `--min-score` or got worse since `--compare`, `2` bad input.

### Use it from Python

```python
import inboxready

report = inboxready.check("yourdomain.com")
print(report.score, report.grade)
for c in report.results:
    print(c.name, c.status, c.summary, c.fix, c.dns_fixes)
```

## What it checks

| Check | What passes | Weight |
|---|---|---|
| **SPF** | One valid `v=spf1` record with correct syntax, 10 or fewer DNS lookups (nested includes counted), no more than 2 empty lookups, ends in `~all` or `-all` | 20 |
| **DKIM** | A working key on one of 40+ common selectors. 1024-bit passes with a tip; under 1024 bits or a cut-off key is flagged | 20 |
| **DMARC** | A record with `p=quarantine` or `p=reject`, `pct=100` and a `rua=` report address. Subdomains inherit from parents (DMARCbis tree walk) and respect `sp=` | 20 |
| **Setup** | Your mailbox provider (Google Workspace, Microsoft 365, Zoho) is authorised in SPF and signing with DKIM | 15 |
| **Blacklists** | Domain not on Spamhaus DBL, URIBL or SURBL; your own sending IPs (from SPF) not on Spamhaus ZEN, SpamCop or Barracuda | 10 |
| **MX** | Can receive replies; detects the mailbox provider | 5 |
| **Domain age** | At least 30 days old and not about to expire | 5 |
| **Website** | The domain resolves, so prospects who look you up find something | 5 |
| **Senders** | Lists every service allowed to send as you (info only) | 0 |
| **Extras** | MTA-STS, TLS-RPT and BIMI (info only) | 0 |

Grades: A is 90+, B is 75+, C is 60+, D is 40+, F is below 40. Checks that can't be completed (a blocklist refusing your resolver, a registry without RDAP) are left out of the score rather than counted against you.

## Getting real blocklist results

Spamhaus and URIBL refuse queries that come through big public resolvers such as Google (8.8.8.8), Cloudflare (1.1.1.1) and Quad9. If your computer uses one of those, the blocklist check will say "unknown" instead of guessing. To get a real answer:

- run it from a network that uses its own resolver, such as most office and ISP networks, or a GitHub Actions runner
- or point it at your ISP's resolver: `inboxready yourdomain.com --nameserver <your ISP DNS IP>`

## Accuracy

Every change is tested on Linux, macOS and Windows, and on Python 3.10 to 3.14. A separate workflow (`scripts/validate_real_domains.py`) runs inboxready against 30+ real domains with live DNS and cross-checks SPF, DMARC and MX results against [checkdmarc](https://github.com/domainaware/checkdmarc), flagging any disagreement.

## Notes and limits

- **DKIM selectors:** DNS can't list every selector, so `inboxready` tries the common ones and detects wildcard records. If yours is custom, find it in a sent email's `DKIM-Signature: s=` header and pass `--selector`.
- **It never sends email.** It only reads public DNS and registration data, so it's safe to run on any domain.

## Contributing

Issues and pull requests are welcome. Good first contributions include adding DKIM selectors, SPF includes for more sending tools, more mailbox providers in `providers.py`, and clearer fix text. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
