"""hook-matcher-probe: static probe for Claude Code hook matchers that never fire."""

from .analyze import analyze_settings, explain_matcher, Finding, Report
from .cli import __version__, main

__all__ = [
    "analyze_settings",
    "explain_matcher",
    "Finding",
    "Report",
    "__version__",
    "main",
]
