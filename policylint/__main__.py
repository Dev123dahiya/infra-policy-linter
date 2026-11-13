"""usage: python -m policylint PATH [--fail-on low|medium|high] [--json]

Exits 1 when any finding is at or above --fail-on (default: medium).
"""
from __future__ import annotations

import argparse
import json
import sys

from .core import RULES, SEVERITY_ORDER
from .scan import lint_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="policylint")
    parser.add_argument("path")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="medium")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    findings, checked, errors = lint_path(args.path)
    blocking = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.fail_on]]
    if args.json:
        print(json.dumps({"files_checked": checked, "findings": [f.as_dict() for f in findings], "unparsed": errors}, indent=2))
    else:
        for f in findings:
            where = f"{f.path}:{f.line}"
            print(f"{f.severity.upper():<6} {f.rule:<7} {where:<26} {f.title}" + (f"  [{f.resource}]" if f.resource else ""))
            print(f"{'':14} {f.detail}. {RULES[f.rule][2]}.")
        for e in errors:
            print(f"SKIP   {e}")
        counts = {s: sum(f.severity == s for f in findings) for s in ("high", "medium", "low")}
        print(f"{checked} file(s) checked: {counts['high']} high, {counts['medium']} medium, {counts['low']} low"
              + (f"; {len(blocking)} at or above '{args.fail_on}'" if findings else ""))
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
