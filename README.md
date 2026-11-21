# inboxready

**Check if a domain is ready for cold email, in one command.**

`inboxready` checks the DNS setup that decides whether your emails land in the inbox or in spam: SPF, DKIM, DMARC, MX records and blocklists. It gives every domain a score out of 100 and tells you in plain English how to fix each problem.

It's built for people who run outbound: growth marketers, SDR teams, agencies and founders setting up new sending domains. It's also handy for developers who want deliverability checks in CI.

```
$ inboxready acme-outreach.com

  acme-outreach.com  85/100 (grade B)

  ✔ SPF        Valid SPF record (4/10 DNS lookups).
  ✔ DKIM       DKIM key found: google.
  ! DMARC      DMARC is p=none (monitoring only). It passes the Gmail/Yahoo rule but does not protect your domain from spoofing.
               Fix: Once SPF and DKIM pass in your reports, move to p=quarantine.
  ✔ MX         1 MX record(s), hosted on Google Workspace.
  ✔ Blacklists Clean on 6 blocklist checks.
  ! Website    Domain has no website. Prospects who check a cold sender's domain find nothing.
               Fix: Point the domain at a simple page or redirect it to your main site.
  i Extras     No MTA-STS, TLS-RPT or BIMI (optional, nice to have).
```

## Why

Since February 2024, Gmail and Yahoo require bulk senders to have SPF, DKIM and DMARC. Most cold email teams run 5 to 50 secondary sending domains, and one bad record quietly sends a whole campaign to spam. Web checkers handle one domain at a time and bury the fix. `inboxready` checks a whole list in seconds and tells you exactly what to change.

## Install

```bash
pip install inboxready
```

Needs Python 3.8+. The only dependency is `dnspython`.

## Usage

```bash
# one domain (an email address or URL works too)
inboxready yourdomain.com

# many domains at once
inboxready getacme.com tryacme.com acmehq.com

# a file with one domain per line (or a CSV with domains in the first column)
inboxready -f sending-domains.csv

# a spreadsheet-friendly summary
inboxready -f sending-domains.csv --csv > report.csv

# your DKIM selector, if it isn't a common one
inboxready yourdomain.com --selector s2024

# full JSON for scripts and dashboards
inboxready yourdomain.com --json

# on a network that blocks DNS (corporate VPN, some clouds)
inboxready yourdomain.com --doh
```

### Use it in CI

Fail a build or a scheduled job when any domain drops below a score:

```bash
inboxready -f domains.txt --min-score 80
```

Exit codes: `0` all good, `1` a domain scored below `--min-score`, `2` bad input.

### Use it from Python

```python
import inboxready

report = inboxready.check("yourdomain.com")
print(report.score, report.grade)
for c in report.results:
    print(c.name, c.status, c.summary, c.fix)
```

## What it checks

| Check | What passes | Weight |
|---|---|---|
| **SPF** | Exactly one `v=spf1` record, 10 or fewer DNS lookups (nested includes counted), ends in `~all` or `-all` | 25 |
| **DMARC** | A `v=DMARC1` record with `p=quarantine` or `p=reject`, `pct=100`, and a `rua=` report address. `p=none` is a warning | 25 |
| **DKIM** | A key on one of 30+ common selectors (Google, Microsoft 365, SendGrid, Mailchimp, Zoho, Brevo and more), 2048-bit or stronger | 20 |
| **Blacklists** | Domain not on Spamhaus DBL, URIBL or SURBL, and mail server IPs not on Spamhaus ZEN, SpamCop or Barracuda | 15 |
| **MX** | Can receive replies, and detects the mailbox provider | 10 |
| **Website** | The domain resolves, so prospects who look you up find something | 5 |
| **Extras** | MTA-STS, TLS-RPT and BIMI (info only, not scored) | 0 |

Grades: A is 90+, B is 75+, C is 60+, D is 40+, F is below 40. Checks that can't be completed, for example a blocklist that refuses public DNS, are left out of the score instead of counting against you.

## Notes and limits

- **DKIM selectors:** DNS has no way to list every selector, so `inboxready` tries the common ones. If you use a custom selector, find it in a sent email's `DKIM-Signature: s=` header and pass `--selector`.
- **Blocklists on public DNS:** Spamhaus refuses queries sent through big public resolvers like 8.8.8.8. In that case the result shows as unknown, not clean. Use your own resolver with `--nameserver` for a real answer.
- **It doesn't send email.** It checks DNS only, so it's safe to run against any domain.

## Contributing

Issues and pull requests are welcome. Good first contributions include adding DKIM selectors for more email tools, adding blocklists and improving the fix text. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
