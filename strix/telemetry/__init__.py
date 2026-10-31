from . import posthog, scarf
from ._common import set_scan_phase


def report_error(error_type: str, exc: BaseException | None = None) -> None:
    """Beacon a failure category, plus the exception class when one is given.

    Only class names travel: never the message, arguments, or traceback.
    """
    posthog.error(error_type, exc)
    scarf.error(error_type, exc)


__all__ = [
    "posthog",
    "report_error",
    "scarf",
    "set_scan_phase",
]
