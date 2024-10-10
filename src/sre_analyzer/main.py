"""Command-line interface for the SRE Log Analyzer.

Usage::

    python main.py --log-file sample_logs/incident_001.log
    python main.py --log-file incident.log -o reports/postmortem.md --json diag.json

Exit codes:
    0 — analysis completed and post-mortem written
    1 — input file missing/unreadable or invalid arguments
    2 — file read, but no log entries could be parsed
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from .diagnostics import analyze
from .log_parser import LogParser
from .postmortem_generator import write_postmortem


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="sre-analyze",
        description=(
            "Parse server error logs (Nginx, Kubernetes, app logs, Python "
            "tracebacks), diagnose the most likely root cause, and generate a "
            "blameless Markdown post-mortem."
        ),
        epilog="Example: python main.py --log-file sample_logs/incident_001.log",
    )
    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to the raw log file to analyze.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="postmortem.md",
        help="Path for the generated Markdown post-mortem (default: %(default)s).",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        default=None,
        help="Optionally also write the raw diagnostic report as JSON.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress the console summary (errors are still printed).",
    )
    return parser


def _print_summary(report_path: Path, report, quiet: bool) -> None:
    """Print a compact console summary of the analysis."""
    if quiet:
        return
    root = report.root_cause
    print("=" * 62)
    print(" SRE Log Analyzer — Incident Diagnosis")
    print("=" * 62)
    print(f" Log file        : {report.source_file}")
    print(
        f" Parsed entries  : {report.total_entries} "
        f"({report.parse_coverage:.1%} line coverage, "
        f"{report.unparsed_count} unparsed)"
    )
    print(f" Log sources     : {', '.join(sorted(report.format_counts)) or 'n/a'}")
    if report.incident_start and report.incident_end:
        print(
            " Incident window : "
            f"{report.incident_start:%H:%M:%S} -> {report.incident_end:%H:%M:%S} "
            f"UTC ({report.duration})"
        )
    print(f" Severity        : {report.incident_severity}")
    if root is not None:
        print(
            f" Root cause      : {root.signature.name} "
            f"[confidence: {report.confidence}]"
        )
    else:
        print(" Root cause      : not identified (no signature matched)")
    print(f" 5xx failures    : {report.failed_requests_5xx}")
    print("-" * 62)
    print(f" Post-mortem written to: {report_path}")
    print("=" * 62)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. Returns a process exit code instead of calling sys.exit."""
    args = build_arg_parser().parse_args(argv)

    try:
        parse_result = LogParser().parse_file(args.log_file)
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not parse_result.entries:
        print(
            f"error: no log entries could be parsed from '{args.log_file}'. "
            "The file may be empty or in an unsupported format.",
            file=sys.stderr,
        )
        return 2

    report = analyze(parse_result, source_file=str(args.log_file))

    try:
        output_path = write_postmortem(report, args.output)
    except OSError as exc:
        print(f"error: could not write post-mortem: {exc}", file=sys.stderr)
        return 1

    if args.json:
        try:
            Path(args.json).write_text(
                json.dumps(report.to_dict(), indent=2), encoding="utf-8"
            )
        except OSError as exc:
            print(f"error: could not write JSON report: {exc}", file=sys.stderr)
            return 1

    _print_summary(output_path, report, args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
