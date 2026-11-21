"""Small DNS wrapper so checks can be tested with a fake resolver."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, List, Optional

import dns.exception
import dns.resolver

# A lookup function takes (name, rtype) and returns a list of strings.
# It returns [] when the name or record does not exist.
# It raises LookupFailed when DNS itself fails (timeout, SERVFAIL).
Lookup = Callable[[str, str], List[str]]


class LookupFailed(Exception):
    """DNS query could not be answered (timeout, SERVFAIL, no nameservers)."""


RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}
DOH_PROVIDERS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}


def _unquote_txt(data: str) -> str:
    data = data.strip()
    if not data.startswith('"'):
        return data
    # TXT data can be split into several quoted chunks: "abc" "def"
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(c.replace('\\"', '"') for c in chunks)


def parse_doh_answer(payload: dict, rtype: str) -> List[str]:
    """Turn a DNS-over-HTTPS JSON response into the same shape make_lookup returns."""
    status = payload.get("Status", 2)
    if status == 3:  # NXDOMAIN
        return []
    if status != 0:
        raise LookupFailed(f"DoH returned DNS status {status}")
    want = RTYPES[rtype]
    out: List[str] = []
    for ans in payload.get("Answer", []) or []:
        if ans.get("type") != want:
            continue
        data = ans.get("data", "")
        if rtype == "TXT":
            out.append(_unquote_txt(data))
        elif rtype == "MX":
            pref, _, host = data.partition(" ")
            out.append(f"{pref} {host.rstrip('.')}")
        else:
            out.append(data.rstrip("."))
    return out


def make_doh_lookup(provider: str = "google", timeout: float = 6.0) -> Lookup:
    """Lookup over HTTPS, for networks that block normal DNS (port 53)."""
    base = DOH_PROVIDERS.get(provider, provider)

    def lookup(name: str, rtype: str) -> List[str]:
        url = f"{base}?{urllib.parse.urlencode({'name': name, 'type': rtype})}"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LookupFailed(f"DoH {rtype} lookup for {name} failed: {exc}") from exc
        return parse_doh_answer(payload, rtype)

    return lookup


def make_lookup(nameservers: Optional[List[str]] = None, timeout: float = 4.0) -> Lookup:
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2

    def lookup(name: str, rtype: str) -> List[str]:
        try:
            answer = resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise LookupFailed(f"{rtype} lookup for {name} failed: {exc.__class__.__name__}") from exc
        out: List[str] = []
        for rdata in answer:
            if rtype == "TXT":
                out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
            elif rtype == "MX":
                out.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
            else:
                out.append(str(rdata).rstrip("."))
        return out

    return lookup
