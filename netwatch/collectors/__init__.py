"""Connection collectors, one per operating system family."""

from __future__ import annotations

from typing import List

from .. import platform as plat
from ..models import Connection
from .base import Collector, CollectorError, get_collector

__all__ = ["Collector", "CollectorError", "get_collector", "collect_connections"]


def collect_connections() -> List[Connection]:
    """Convenience wrapper: pick the right collector for this host and read it."""

    return get_collector().collect()
