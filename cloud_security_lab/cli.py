"""Cross-platform assessment, detection, verification and demo commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .errors import FixtureError
from .reporting import render, write_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Synthetic cloud security engineering lab")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("assess", "detect", "verify"):
        sub = subparsers.add_parser(command)
        if command == "verify":
            sub.add_argument("before", type=Path)
            sub.add_argument("after", type=Path)
        else:
            sub.add_argument("source", type=Path)
            sub.add_argument("--fail-on-findings", action="store_true")
        sub.add_argument("--format", choices=("text", "json", "markdown"), default="text")
        sub.add_argument("--output", type=Path)
    demo = subparsers.add_parser("demo")
    demo.add_argument("--root", type=Path, default=Path("."))
    demo.add_argument("--output-dir", type=Path, default=Path("artifacts/demo"))
    demo.add_argument("--check", type=Path, help="Compare with existing generated evidence")
    validate = subparsers.add_parser("validate-fixtures")
    validate.add_argument("--root", type=Path, default=Path("."))
    return parser


def _run(args: argparse.Namespace) -> int:
    data: dict[str, Any]
    failed = False
    if args.command == "demo":
        from .demo import run_demo

        summary = run_demo(args.root, args.check or args.output_dir, check=args.check is not None)
        print(
            f"Synthetic demo: {summary['controls']} controls; "
            f"{summary['risky_findings']} findings -> "
            f"{summary['verified_closed']} VERIFIED_CLOSED; "
            f"{summary['alerts']} alerts; {summary['correlations']} correlation(s)."
        )
        print(f"Evidence {'checked' if args.check else 'written'}: {args.check or args.output_dir}")
        return 0
    if args.command == "validate-fixtures":
        from .validation import validate_fixtures

        print(render(validate_fixtures(args.root), "json"), end="")
        return 0
    if args.command == "detect":
        from .detections import detect
        from .events import load_events

        data = detect(load_events(args.source)).to_dict()
        failed = args.fail_on_findings and bool(data["alerts"])
    else:
        from .fixtures import load_snapshot

        if args.command == "assess":
            from .posture import assess

            data = assess(load_snapshot(args.source)).to_dict()
            failed = args.fail_on_findings and bool(data["findings"])
        else:
            from .remediation import verify

            data = verify(load_snapshot(args.before), load_snapshot(args.after))
            failed = not data["success"]
    if args.output:
        write_report(args.output, data, args.format)
    else:
        print(render(data, args.format), end="")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except (FixtureError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
