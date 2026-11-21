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
from .report import Report, normalize_domain, run

ICONS = {"pass": "✔", "warn": "!", "fail": "✘", "info": "i", "unknown": "?"}
COLORS = {"pass": "32", "warn": "33", "fail": "31", "info": "36", "unknown": "90"}


def _use_color(stream) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


def _c(text: str, code: str, color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if color else text


def render(report: Report, color: bool, verbose: bool = False) -> str:
    grade_color = {"A": "32", "B": "32", "C": "33", "D": "31", "F": "31"}[report.grade]
    lines = [
        "",
        _c(f"  {report.domain}", "1", color)
        + "  "
        + _c(f"{report.score}/100 (grade {report.grade})", grade_color, color),
        "",
    ]
    for r in report.results:
        icon = _c(ICONS[r.status], COLORS[r.status], color)
        lines.append(f"  {icon} {r.name:<11}{r.summary}")
        if r.fix and r.status in ("fail", "warn", "unknown"):
            lines.append(_c(f"    {'':<11}Fix: {r.fix}", "90", color))
        if verbose and r.details:
            for k, v in r.details.items():
                lines.append(_c(f"    {'':<11}{k}: {v}", "90", color))
    lines.append("")
    return "\n".join(lines)


def _read_domains(path: str) -> List[str]:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    out = []
    for row in rows:
        if row and row[0].strip() and not row[0].strip().startswith("#"):
            out.append(row[0].strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="inboxready",
        description="Check if a domain is ready for cold email: SPF, DKIM, DMARC, MX, blocklists.",
    )
    p.add_argument("domains", nargs="*", help="domains or email addresses to check")
    p.add_argument("-f", "--file", help="file with one domain per line (CSV first column also works)")
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
        raw += _read_domains(args.file)
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
    with ThreadPoolExecutor(max_workers=min(8, len(domains))) as pool:
        reports = list(pool.map(
            lambda d: run(d, lookup, args.selector, not args.no_blacklist), domains))

    if args.json:
        data = [r.to_dict() for r in reports]
        print(json.dumps(data[0] if len(data) == 1 else data, indent=2))
    elif args.csv:
        names = [c.name for c in reports[0].results]
        w = csv.writer(sys.stdout)
        w.writerow(["domain", "score", "grade"] + names)
        for r in reports:
            w.writerow([r.domain, r.score, r.grade] + [c.status for c in r.results])
    else:
        color = _use_color(sys.stdout)
        for r in reports:
            print(render(r, color, args.verbose))

    if args.min_score is not None and any(r.score < args.min_score for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
