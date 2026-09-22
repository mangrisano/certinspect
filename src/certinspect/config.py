"""Loading and validating the --config TOML file.

A config file supplies default option values that an explicit command-line
flag still overrides. Its keys are checked against the live parser so a typo is
caught rather than silently ignored.
"""

import argparse
import tomllib
from pathlib import Path

# Default location for --config, checked only when the flag is not given.
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "certinspect" / "config.toml"

# Destination groups the parser makes mutually exclusive: a --config file
# setting more than one member of a group would silently defeat argparse's own
# check (which only inspects command-line flags, not defaults), so it is
# re-checked here. Kept in sync with the mutually exclusive groups in
# build_parser().
_CONFIG_EXCLUSIVE_GROUPS = (
    ("json", "field", "csv", "exporter"),
    ("not_after_max", "cab_forum"),
)


def load_config(path: str, parser: argparse.ArgumentParser) -> dict:
    """Load a --config TOML file and return it as a dest -> value mapping.

    Every key must be a known argparse destination (checked against ``parser``
    so a typo is caught instead of silently ignored) and no key may collide
    with another inside the same mutually exclusive group. Raises ValueError
    on any I/O, parse or validation failure; the caller turns that into a
    normal ``parser.error``.
    """
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except OSError as err:
        raise ValueError(f"could not read config file {path}: {err}") from err
    except tomllib.TOMLDecodeError as err:
        raise ValueError(f"could not parse config file {path}: {err}") from err
    if not isinstance(data, dict):
        raise ValueError(f"config file {path} must be a table of key = value pairs")

    # `_actions` is argparse's own private registry of every added argument;
    # there is no public way to enumerate destinations.
    valid_dests = {
        action.dest
        for action in parser._actions
        if action.dest not in ("help", "target", "config")
    }
    unknown = sorted(set(data) - valid_dests)
    if unknown:
        raise ValueError(
            f"config file {path} sets unknown option(s): {', '.join(unknown)}"
        )
    for group in _CONFIG_EXCLUSIVE_GROUPS:
        present = [name for name in group if name in data]
        if len(present) > 1:
            raise ValueError(
                f"config file {path} sets mutually exclusive options: "
                f"{', '.join(present)}"
            )
    return data
