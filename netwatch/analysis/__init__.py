"""Analysis pipeline: turns raw connections into graded, flagged results."""

from __future__ import annotations

from .engine import AnalysisEngine, analyze_connections

__all__ = ["AnalysisEngine", "analyze_connections"]
