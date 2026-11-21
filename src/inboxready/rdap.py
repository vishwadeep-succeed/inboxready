"""Domain registration dates over RDAP (the free, keyless successor to WHOIS)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable, Optional, Tuple

# Takes a domain, returns the parsed RDAP JSON, or None when the registry has no record.
# Raises RdapUnavailable when the lookup itself fails.
Fetch = Callable[[str], Optional[dict]]

RDAP_URL = "https://rdap.org/domain/{}"


class RdapUnavailable(Exception):
    pass


def default_fetch(domain: str, timeout: float = 8.0) -> Optional[dict]:
    req = urllib.request.Request(
        RDAP_URL.format(domain),
        headers={"accept": "application/rdap+json, application/json", "user-agent": "inboxready"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RdapUnavailable(f"RDAP returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RdapUnavailable(f"RDAP lookup failed: {exc}") from exc


def _parse_date(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def registration_dates(domain: str, fetch: Fetch) -> Tuple[Optional[str], Optional[datetime], Optional[datetime]]:
    """Return (registered_domain, created, expires). Walks up from subdomains to the registered name."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        data = fetch(name)
        if data is None:
            continue
        created = expires = None
        for ev in data.get("events", []) or []:
            action = (ev.get("eventAction") or "").lower()
            when = _parse_date(ev.get("eventDate", ""))
            if action == "registration" and when:
                created = when
            elif action == "expiration" and when:
                expires = when
        return name, created, expires
    return None, None, None
