"""Command line interface: inboxready example.com"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from . import __version__
from .dnsutil import make_doh_lookup, make_lookup
from .report import CHECK_NAMES, Report, normalize_domain, run

ICONS = {"pass": "✔", "warn": "!", "fail": "✘", "info": "i", "unknown": "?"}
ASCII_ICONS = {"pass": "+", "warn": "!", "fail": "x", "info": "i", "unknown": "?"}
DOMAIN_COLUMNS = ("domain", "domains", "website", "company domain", "company_domain", "url",
                  "email", "email address", "work email", "sending domain")
COLORS = {"pass": "32", "warn": "33", "fail": "31", "info": "36", "unknown": "90"}


def _use_color(stream) -> bool:
    if "NO_COLOR" in os.environ or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        os.system("")  # turns on ANSI colour support in Windows 10+ consoles
    return True


def _icons_for(stream) -> dict:
    """Use plain ASCII icons when the console can't print the unicode ones (older Windows)."""
    try:
        "✔✘".encode(getattr(stream, "encoding", None) or "ascii")
        return ICONS
    except (UnicodeEncodeError, LookupError):
        return ASCII_ICONS


def _c(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def render(report: Report, color: bool, verbose: bool = False, icons: Optional[dict] = None) -> str:
    icons = icons or ICONS
    grade_color = {"A": "32", "B": "32", "C": "33", "D": "31", "F": "31"}[report.grade]
    lines = [
        "",
        _c(f"  {report.domain}", "1", color)
        + "  "
        + _c(f"{report.score}/100 (grade {report.grade})", grade_color, color),
        "",
    ]
    for r in report.results:
        icon = _c(icons[r.status], COLORS[r.status], color)
        lines.append(f"  {icon} {r.name:<11}{r.summary}")
        if r.fix and r.status in ("fail", "warn", "unknown"):
            lines.append(_c(f"    {'':<11}Fix: {r.fix}", "90", color))
        if verbose and r.details:
            for k, v in r.details.items():
                lines.append(_c(f"    {'':<11}{k}: {v}", "90", color))
    lines.append("")
    return "\n".join(lines)


def _read_domains(path: str, column: Optional[str] = None) -> List[str]:
    """Read domains from a text or CSV file. Handles Excel's BOM and finds a domain/email column."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = [r for r in csv.reader(fh) if r and r[0].strip() and not r[0].strip().startswith("#")]
    if not rows:
        return []
    header = [c.strip().lower() for c in rows[0]]
    col = 0
    if column is not None:
        if column.lower() in header:
            col = header.index(column.lower())
        elif column.isdigit():
            col = int(column) - 1
        else:
            raise ValueError(f"column '{column}' not found in {path}")
        if column.lower() in header:
            rows = rows[1:]
    elif any(h in DOMAIN_COLUMNS for h in header):
        col = next(i for i, h in enumerate(header) if h in DOMAIN_COLUMNS)
        rows = rows[1:]
    elif "." not in rows[0][0]:
        rows = rows[1:]  # an unrecognised header row
    return [r[col].strip() for r in rows if len(r) > col and r[col].strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="inboxready",
        description="Check if a domain is ready for cold email: SPF, DKIM, DMARC, MX, blocklists.",
    )
    p.add_argument("domains", nargs="*", help="domains or email addresses to check")
    p.add_argument("-f", "--file", help="text file with one domain per line, or a CSV (e.g. a lead export)")
    p.add_argument("-c", "--column", help="CSV column to read (header name or number); auto-detected by default")
    p.add_argument("-s", "--selector", action="append", help="DKIM selector to check (repeatable)")
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument("--csv", action="store_true", help="output a CSV summary (good for many domains)")
    p.add_argument("-v", "--verbose", action="store_true", help="show raw records and details")
    p.add_argument("--no-blacklist", action="store_true", help="skip blocklist lookups")
    p.add_argument("--nameserver", action="append", help="DNS server IP to use (repeatable)")
    p.add_argument("--doh", nargs="?", const="google", metavar="PROVIDER",
                   help="resolve over HTTPS (google or cloudflare) for networks that block DNS")
    p.add_argument("--min-score", type=int, help="exit with code 1 if any domain scores below this")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    raw = list(args.domains)
    if args.file:
        try:
            raw += _read_domains(args.file, args.column)
        except (OSError, ValueError) as exc:
            print(f"inboxready: {exc}", file=sys.stderr)
            return 2
    if not raw:
        build_parser().print_help()
        return 2

    domains, errors = [], []
    for d in raw:
        try:
            nd = normalize_domain(d)
            if nd not in domains:
                domains.append(nd)
        except ValueError as exc:
            errors.append(str(exc))
    for e in errors:
        print(f"inboxready: {e}", file=sys.stderr)
    if not domains:
        return 2

    lookup = make_doh_lookup(args.doh) if args.doh else make_lookup(args.nameserver)
    with ThreadPoolExecutor(max_workers=min(6, len(domains))) as pool:
        reports = list(pool.map(
            lambda d: run(d, lookup, args.selector, not args.no_blacklist), domains))

    if args.json:
        data = [r.to_dict() for r in reports]
        print(json.dumps(data[0] if len(data) == 1 else data, indent=2))
    elif args.csv:
        w = csv.writer(sys.stdout, lineterminator="\n")
        w.writerow(["domain", "score", "grade", "note"] + CHECK_NAMES)
        for r in reports:
            by_name = {c.name: c.status for c in r.results}
            note = "domain not found" if "Domain" in by_name else ""
            w.writerow([r.domain, r.score, r.grade, note] + [by_name.get(n, "") for n in CHECK_NAMES])
    else:
        color = _use_color(sys.stdout)
        icons = _icons_for(sys.stdout)
        for r in reports:
            print(render(r, color, args.verbose, icons))

    if args.min_score is not None and any(r.score < args.min_score for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
