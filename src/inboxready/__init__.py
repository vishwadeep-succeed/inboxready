"""inboxready: check if a domain is ready for cold email."""

__version__ = "0.1.0"

from .report import Report, run  # noqa: E402,F401
from .dnsutil import make_lookup  # noqa: E402,F401


def check(domain: str, selectors=None, blacklists: bool = True, nameservers=None) -> "Report":
    """Run every check on a domain and return a Report."""
    return run(domain, make_lookup(nameservers), selectors, blacklists)
