"""Process exit codes and the status-to-code mapping.

Single source of truth for the exit codes certinspect returns, so the
orchestration (cli) and the reporters (formatter) agree on what each number
means instead of repeating the literals.
"""

from enum import IntEnum, StrEnum


class ExitCode(IntEnum):
    """Exit code reflecting the worst certificate state found.

    Kept distinct from argparse's usage error (2) and the generic runtime
    error (1), which are not certificate states and stay plain integers.
    """

    OK = 0
    EXPIRING = 3
    INVALID = 4  # expired, critical, not-yet-valid or invalid dates
    HOSTNAME_MISMATCH = 5
    UNTRUSTED_OR_REVOKED = 6
    PIN_MISMATCH = 7
    SAN_MISMATCH = 8
    POLICY = 9


class Status(StrEnum):
    """Certificate validity status returned by ``certificate_status``.

    A ``StrEnum`` so each member still *is* its plain string ("EXPIRED", ...),
    keeping the JSON output and every existing string comparison unchanged
    while giving one authoritative definition of the status set.
    """

    VALID = "VALID"
    EXPIRING = "EXPIRING"
    CRITICAL = "CRITICAL"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT YET VALID"
    INVALID_DATES = "INVALID DATES"


# Validity status mapped to its exit code; the four non-valid date states all
# share ExitCode.INVALID.
EXIT_BY_STATUS: dict[Status, ExitCode] = {
    Status.VALID: ExitCode.OK,
    Status.EXPIRING: ExitCode.EXPIRING,
    Status.CRITICAL: ExitCode.INVALID,
    Status.EXPIRED: ExitCode.INVALID,
    Status.INVALID_DATES: ExitCode.INVALID,
    Status.NOT_YET_VALID: ExitCode.INVALID,
}
