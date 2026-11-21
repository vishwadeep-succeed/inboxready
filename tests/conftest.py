import pytest

from inboxready import rdap


@pytest.fixture(autouse=True)
def no_network_rdap(monkeypatch):
    """Tests never touch the network: RDAP behaves as if it were unreachable unless a test injects data."""

    def offline(domain, timeout=8.0):
        raise rdap.RdapUnavailable("offline in tests")

    monkeypatch.setattr(rdap, "default_fetch", offline)
