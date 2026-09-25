"""Persist per-target status across runs for --state-file / --only-changed."""

import json
import sys

from certinspect.models import InspectionResult


def update_state(
    path: str,
    results: list[InspectionResult],
    errors: list[tuple[str | None, str]],
) -> set[str]:
    """Save this run's statuses to ``path`` and return the targets that changed.

    A target that failed this run keeps its last known status, so a transient
    outage is not reported as a change once it recovers. Targets no longer in
    the run are dropped.
    """
    previous = load_state(path)
    current = {r.label: r.info["status"] for r in results if r.label is not None}
    changed = {t for t, status in current.items() if previous.get(t) != status}
    failed = {name for name, _ in errors}
    kept = {t: s for t, s in previous.items() if t in failed}
    save_state(path, {**kept, **current})
    return changed


def load_state(path: str) -> dict[str, str]:
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


def save_state(path: str, state: dict[str, str]) -> None:
    """Persist the target -> status mapping for the next --state-file run.

    Failing to write is reported as a warning rather than aborting the run:
    the inspection results themselves are unaffected.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
    except OSError as err:
        print(f"warning: could not write --state-file {path}: {err}", file=sys.stderr)
