"""SRE Log Analyzer — automated incident diagnostics and post-mortem drafting."""

from .diagnostics import DiagnosticReport, analyze
from .log_parser import LogEntry, LogParser, ParseResult, Severity
from .postmortem_generator import render_markdown, write_postmortem

__version__ = "1.0.0"

__all__ = [
    "DiagnosticReport",
    "LogEntry",
    "LogParser",
    "ParseResult",
    "Severity",
    "analyze",
    "render_markdown",
    "write_postmortem",
    "__version__",
]
