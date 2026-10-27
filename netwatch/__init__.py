"""NetWatch - live, cross-platform network connection monitor."""

from .models import (  # noqa: F401
    Connection,
    Endpoint,
    Flag,
    PermissionCheck,
    PlatformReport,
    ProcessInfo,
    ScanSummary,
    Verdict,
)

__version__ = "1.0.0"
__all__ = [
    "Connection",
    "Endpoint",
    "Flag",
    "PermissionCheck",
    "PlatformReport",
    "ProcessInfo",
    "ScanSummary",
    "Verdict",
    "__version__",
]
