"""Render inspection results and persist per-run state.

Turns the collected ``(target, info, exit_code)`` results into the selected
output (human text, JSON, CSV, tab-separated fields, or a monitoring exporter)
and reads/writes the optional --state-file used to detect status changes across
runs. Presentation only; the analysis lives in parser/formatter.
"""

import json
import sys

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


def _render(
    results: list[tuple[str | None, dict, int]],
    *,
    as_json: bool,
    days: int,
    quiet: bool,
    as_csv: bool = False,
    csv_delimiter: str = ",",
    critical_days: int | None = None,
    max_days: int | None = None,
    sort: str | None = None,
    summary: bool = False,
    exporter: str | None = None,
    fields: list[str] | None = None,
    schema: int = 2,
    errors: list[tuple[str | None, str]] = (),
    changed_targets: set[str] | None = None,
) -> int | None:
    """Print the collected results and return an optional exit-code override.

    With ``exporter`` set, render monitoring output: 'nagios' returns its
    plugin exit code (the override), 'prometheus' returns None. Otherwise
    print the selected ``fields`` (tab-separated), JSON, CSV, or human text;
    ``quiet`` keeps only results with a non-zero exit code and ``max_days``
    keeps only those expiring within that many days. ``changed_targets``, when
    not None, keeps only results whose target is in the set (the caller passes
    it only when --only-changed is given). ``sort`` reorders the kept results
    ('host' or 'expiry'). All these affect the display only, never the exit
    code. ``summary`` prints a one-line tally to stderr, counting every target
    before filtering.
    """
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
        if summary
        else None
    )

    if quiet:
        results = [r for r in results if r[2] != 0]
    if max_days is not None:
        results = [r for r in results if r[1]["days_to_expire"] <= max_days]
    if changed_targets is not None:
        results = [r for r in results if r[0] in changed_targets]
    if sort == "host":
        results = sorted(results, key=lambda r: r[0] or "")
    elif sort == "expiry":
        results = sorted(results, key=lambda r: r[1]["days_to_expire"])

    if fields:
        text = format_fields(results, fields)
        if text:
            print(text)
    elif as_csv:
        print(
            format_csv(
                results,
                warn_days=days,
                delimiter=csv_delimiter,
                critical_days=critical_days,
            ),
            end="",
        )
    elif as_json:
        if schema == 1:
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


def _load_state(path: str) -> dict[str, str]:
    """Return the target -> status mapping saved by a previous --state-file run.

    A missing, unreadable or malformed file is treated as an empty history (the
    first run establishes the baseline) rather than an error.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(path: str, state: dict[str, str]) -> None:
    """Persist the target -> status mapping for the next --state-file run.

    Failing to write is reported as a warning rather than aborting the run:
    the inspection results themselves are unaffected.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
    except OSError as err:
        print(f"warning: could not write --state-file {path}: {err}", file=sys.stderr)
