"""Loading and validating the --config TOML file.

A config file supplies default option values that an explicit command-line
flag still overrides. Its keys, types, choices and mutually exclusive groups
are checked against the live parser so typos or invalid values are caught
rather than silently ignored or crashing at runtime.
"""

import argparse
import tomllib
from pathlib import Path

# Default location for --config, checked only when the flag is not given.
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "certinspect" / "config.toml"


# Mutually exclusive pairs enforced in _validate_args rather than argparse.
_EXTRA_EXCLUSIVE_GROUPS: tuple[tuple[str, ...], ...] = (("proxy", "no_proxy"),)


def exclusive_groups(parser: argparse.ArgumentParser) -> list[tuple[str, ...]]:
    """Return mutually exclusive destination groups derived from ``parser``."""
    groups: list[tuple[str, ...]] = []
    for group in parser._mutually_exclusive_groups:
        dests = tuple(dict.fromkeys(action.dest for action in group._group_actions))
        if len(dests) > 1:
            groups.append(dests)
    groups.extend(_EXTRA_EXCLUSIVE_GROUPS)
    return groups


def _validate_value(
    path: str, key: str, value: object, action: argparse.Action
) -> None:
    """Validate that ``value`` matches the expected type and choices of ``action``."""
    if isinstance(action, (argparse._StoreTrueAction, argparse._StoreFalseAction)):
        if not isinstance(value, bool):
            raise ValueError(
                f"config file {path} sets {key!r} to {type(value).__name__}, "
                "expected bool"
            )
        return

    if isinstance(action, argparse._AppendAction):
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise ValueError(
                f"config file {path} sets {key!r} to invalid value, "
                "expected list of strings"
            )
        return

    if action.type is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"config file {path} sets {key!r} to {type(value).__name__}, "
                "expected int"
            )
    elif action.type is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"config file {path} sets {key!r} to {type(value).__name__}, "
                "expected number"
            )
    elif action.type is None:
        if not isinstance(value, str):
            raise ValueError(
                f"config file {path} sets {key!r} to {type(value).__name__}, "
                "expected string"
            )

    if action.choices is not None and value not in action.choices:
        allowed = ", ".join(repr(c) for c in action.choices)
        raise ValueError(
            f"config file {path} sets invalid value for {key!r}: {value!r} "
            f"(choose from {allowed})"
        )


def load_config(path: str, parser: argparse.ArgumentParser) -> dict:
    """Load a --config TOML file and return it as a dest -> value mapping.

    Every key must be a known argparse destination (checked against ``parser``
    so a typo is caught instead of silently ignored), every value must match
    its option's type and choices, and no key may collide with another inside
    the same mutually exclusive group. Raises ValueError on any I/O, parse or
    validation failure; the caller turns that into a normal ``parser.error``.
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
    actions_by_dest = {
        action.dest: action
        for action in parser._actions
        if action.dest
        not in ("help", "version", "target", "config", "print_completion")
    }
    unknown = sorted(set(data) - set(actions_by_dest))
    if unknown:
        raise ValueError(
            f"config file {path} sets unknown option(s): {', '.join(unknown)}"
        )
    for key, value in data.items():
        _validate_value(path, key, value, actions_by_dest[key])
    for group in exclusive_groups(parser):
        present = [name for name in group if name in data]
        if len(present) > 1:
            raise ValueError(
                f"config file {path} sets mutually exclusive options: "
                f"{', '.join(present)}"
            )
    return data
