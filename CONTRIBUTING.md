# Contributing to inboxready

Thanks for helping. Small, focused pull requests are easiest to review.

## Setup

```bash
git clone https://github.com/vishwadeep-succeed/inboxready
cd inboxready
pip install -e ".[dev]"
pytest
```

## Easy first contributions

- **DKIM selectors:** add the selector your email tool uses to `COMMON_SELECTORS` in `src/inboxready/checks.py`.
- **Mailbox providers:** add MX host suffixes to `PROVIDERS`.
- **Blocklists:** add a list to `DOMAIN_BLS` or `IP_BLS` along with the return codes that mean "listed".
- **Fix text:** make a fix message clearer for non-technical users.

## Rules

- Every check must work with a fake `lookup(name, rtype)` function so tests never touch the network. See `tests/test_checks.py`.
- Add a test for any new behaviour.
- Keep the only runtime dependency as `dnspython`.
