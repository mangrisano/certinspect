"""Render inspection results.

Turns the collected ``(target, info, exit_code)`` results into the selected
output (human text, JSON, CSV, tab-separated fields, or a monitoring exporter).
Presentation only; the analysis lives in parser/formatter.
"""

import argparse
import sys
from dataclasses import dataclass

from certinspect import __version__
from certinspect.formatter import (
    format_csv,
    format_fields,
    format_human,
    format_json,
    format_json_v2,
    format_nagios,
    format_prometheus,
    format_summary,
)
from certinspect.models import InspectionResult


@dataclass(frozen=True)
class OutputOptions:
    """How the results are displayed; never affects the exit code."""

    days: int = 30
    critical_days: int | None = None
    as_json: bool = False
    as_csv: bool = False
    csv_delimiter: str = ","
    schema: int = 2
    exporter: str | None = None
    fields: list[str] | None = None
    quiet: bool = False
    max_days: int | None = None
    sort: str | None = None
    summary: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "OutputOptions":
        """Build the options from parsed CLI arguments."""
        return cls(
            days=args.days,
            critical_days=args.critical_days,
            as_json=args.json,
            as_csv=args.csv,
            csv_delimiter=args.csv_delimiter,
            schema=args.schema,
            exporter=args.exporter,
            fields=args.field,
            quiet=args.quiet,
            max_days=args.max_days,
            sort=args.sort,
            summary=args.summary,
        )


def render(
    results: list[InspectionResult],
    errors: list[tuple[str | None, str]],
    opts: OutputOptions,
    changed_targets: set[str] | None = None,
) -> int | None:
    """Print the collected results and return an optional exit-code override.

    With an exporter, render monitoring output: 'nagios' returns its plugin
    exit code (the override), 'prometheus' returns None. Otherwise print the
    selected fields (tab-separated), JSON, CSV, or human text; --quiet keeps
    only results with a non-zero exit code and --max-days keeps only those
    expiring within that many days. ``changed_targets``, when not None, keeps
    only results whose target is in the set (the caller passes it only when
    --only-changed is given). --sort reorders the kept results. --summary
    prints a one-line tally to stderr, counting every target before filtering.
    """
    days = opts.days
    critical_days = opts.critical_days
    exporter = opts.exporter
    if exporter == "nagios":
        text, code = format_nagios(
            results, errors, warn_days=days, critical_days=critical_days
        )
        print(text)
        return code
    if exporter == "prometheus":
        print(format_prometheus(results, errors, warn_days=days))
        return None

    # Computed from the full result set, before --quiet/--max-days filtering.
    summary_line = (
        format_summary(results, errors, warn_days=days, critical_days=critical_days)
        if opts.summary
        else None
    )

    if opts.quiet:
        results = [r for r in results if r.code != 0]
    if opts.max_days is not None:
        results = [r for r in results if r.info["days_to_expire"] <= opts.max_days]
    if changed_targets is not None:
        results = [r for r in results if r.label in changed_targets]
    if opts.sort == "host":
        results = sorted(results, key=lambda r: r.label or "")
    elif opts.sort == "expiry":
        results = sorted(results, key=lambda r: r.info["days_to_expire"])

    if opts.fields:
        text = format_fields(results, opts.fields)
        if text:
            print(text)
    elif opts.as_csv:
        print(
            format_csv(
                results,
                warn_days=days,
                delimiter=opts.csv_delimiter,
                critical_days=critical_days,
            ),
            end="",
        )
    elif opts.as_json:
        if opts.schema == 1:
            print(format_json([info for _, info, _ in results]))
        else:
            print(format_json_v2(results, version=__version__))
    else:
        blocks = []
        for target, info, _ in results:
            text = format_human(info, warn_days=days, critical_days=critical_days)
            blocks.append(f"=== {target} ===\n{text}" if target else text)
        if blocks:
            print("\n\n".join(blocks))

    if summary_line:
        print(summary_line, file=sys.stderr)
    return None
