"""Knowledge about mailbox providers and sending tools, used to explain what a domain is set up for."""

from __future__ import annotations

from typing import Dict, List, Optional

# MX host suffix -> mailbox provider
MAILBOX_BY_MX = {
    "google.com": "Google Workspace", "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365", "mx.microsoft": "Microsoft 365", "zoho.com": "Zoho Mail", "zoho.in": "Zoho Mail", "zoho.eu": "Zoho Mail",
    "zoho.com.au": "Zoho Mail", "protonmail.ch": "Proton Mail", "messagingengine.com": "Fastmail",
    "mimecast.com": "Mimecast", "pphosted.com": "Proofpoint", "secureserver.net": "GoDaddy",
    "titan.email": "Titan", "icloud.com": "iCloud", "yandex.net": "Yandex", "amazonaws.com": "Amazon SES",
    "zohomail.com": "Zoho Mail", "hostinger.com": "Hostinger", "migadu.com": "Migadu",
}

# SPF include suffix -> service allowed to send as the domain
SENDER_BY_INCLUDE = {
    "_spf.google.com": "Google Workspace", "spf.protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail", "zoho.in": "Zoho Mail", "zoho.eu": "Zoho Mail",
    "zohomail.com": "Zoho Mail", "zohomail.in": "Zoho Mail", "zohomail.eu": "Zoho Mail",
    "zcsend.net": "Zoho Campaigns", "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun",
    "amazonses.com": "Amazon SES", "servers.mcsv.net": "Mailchimp", "mandrillapp.com": "Mandrill",
    "hubspotemail.net": "HubSpot", "_spf.salesforce.com": "Salesforce", "exacttarget.com": "Salesforce Marketing Cloud",
    "aspmx.pardot.com": "Pardot", "mktomail.com": "Marketo", "mailjet.com": "Mailjet",
    "sendinblue.com": "Brevo", "brevo.com": "Brevo", "mtasv.net": "Postmark", "sparkpostmail.com": "SparkPost",
    "_spf.createsend.com": "Campaign Monitor", "mlsend.com": "MailerLite", "constantcontact.com": "Constant Contact",
    "mail.zendesk.com": "Zendesk", "freshdesk.com": "Freshdesk", "freshemail.io": "Freshworks",
    "intercom.io": "Intercom", "helpscoutemail.com": "Help Scout", "klaviyomail.com": "Klaviyo",
    "customeriomail.com": "Customer.io", "_spf.atlassian.net": "Atlassian", "messagingengine.com": "Fastmail",
    "secureserver.net": "GoDaddy", "titan.email": "Titan", "smtp2go.com": "SMTP2GO",
    "elasticemail.com": "Elastic Email", "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast",
    "protonmail.ch": "Proton Mail", "icloud.com": "iCloud", "mailchannels.net": "MailChannels",
    "registrar-servers.com": "Namecheap email forwarding", "emailsrvr.com": "Rackspace",
    "outlook.com": "Microsoft 365",
}

# DKIM selector -> service that usually signs with it
SENDER_BY_SELECTOR = {
    "google": "Google Workspace", "selector1": "Microsoft 365", "selector2": "Microsoft 365",
    "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp", "s1": "SendGrid", "s2": "SendGrid",
    "mandrill": "Mandrill", "hs1": "HubSpot", "hs2": "HubSpot", "zoho": "Zoho Mail", "zmail": "Zoho Mail",
    "pm": "Postmark", "mailjet": "Mailjet", "brevo1": "Brevo", "brevo2": "Brevo", "sig1": "iCloud",
    "fm1": "Fastmail", "fm2": "Fastmail", "protonmail": "Proton Mail", "ses": "Amazon SES",
    "everlytickey1": "Everlytic", "mxvm": "Mailchimp",
}

# How each mailbox provider must be set up for mail from your own mailboxes to authenticate.
SETUP: Dict[str, dict] = {
    "Google Workspace": {
        "spf_include": "_spf.google.com",
        "selectors": ["google"],
        "dkim_steps": "Google Admin > Apps > Google Workspace > Gmail > Authenticate email > "
                      "Generate new record (2048-bit). Add the TXT record it shows, wait an hour, "
                      "then click Start authentication.",
        "mx": [("1", "smtp.google.com")],
    },
    "Microsoft 365": {
        "spf_include": "spf.protection.outlook.com",
        "selectors": ["selector1", "selector2"],
        "dkim_steps": "Microsoft Defender portal > Email & collaboration > Policies & rules > "
                      "Threat policies > Email authentication settings > DKIM. Publish the two "
                      "CNAME records it shows (selector1 and selector2), then enable signing.",
        "mx": None,  # tenant-specific host, shown in the Microsoft 365 admin centre
    },
    "Zoho Mail": {
        "spf_include": "zohomail.com",
        "spf_accept": ("zoho", "zohomail"),
        "selectors": ["zmail", "zoho"],
        "dkim_steps": "Zoho Mail Admin Console > Domains > your domain > Email configuration > "
                      "DKIM > Add selector, publish the TXT record, then Verify.",
        "mx": None,
    },
}


def _match(host: str, table: Dict[str, str]) -> Optional[str]:
    host = host.lower().rstrip(".")
    for suffix, name in table.items():
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


def mailbox_provider(mx_hosts: List[str]) -> Optional[str]:
    for h in mx_hosts:
        p = _match(h, MAILBOX_BY_MX)
        if p:
            return p
    return None


def sender_for_include(include: str) -> Optional[str]:
    return _match(include, SENDER_BY_INCLUDE)


def spf_authorizes(provider: str, includes: List[str]) -> bool:
    setup = SETUP.get(provider)
    if not setup:
        return True
    accept = setup.get("spf_accept")
    for inc in includes:
        inc = inc.lower()
        if inc == setup["spf_include"] or inc.endswith("." + setup["spf_include"]):
            return True
        if accept and any(a in inc for a in accept):
            return True
    return False
