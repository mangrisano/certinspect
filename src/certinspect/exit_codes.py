"""Process exit codes and the status-to-code mapping.

Single source of truth for the exit codes certinspect returns, so the
orchestration (cli) and the reporters (formatter) agree on what each number
means instead of repeating the literals.
"""

from enum import IntEnum


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


# Validity status (from certificate_status) mapped to its exit code; the four
# non-valid date states all share ExitCode.INVALID.
EXIT_BY_STATUS: dict[str, ExitCode] = {
    "VALID": ExitCode.OK,
    "EXPIRING": ExitCode.EXPIRING,
    "CRITICAL": ExitCode.INVALID,
    "EXPIRED": ExitCode.INVALID,
    "INVALID DATES": ExitCode.INVALID,
    "NOT YET VALID": ExitCode.INVALID,
}
