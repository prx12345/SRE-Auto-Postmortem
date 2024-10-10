"""Structured parsing of heterogeneous server logs.

This module converts raw, mixed-format log files into a normalized stream of
:class:`LogEntry` records that downstream diagnostics can reason about.

Supported formats (auto-detected per line):

* **Application logs** ``2026-08-12 14:03:12,540 ERROR [db-pool] message``
* **Nginx error logs** ``2026/08/12 14:04:31 [error] 412#412: message``
* **Nginx access logs** ``10.0.1.21 - - [12/Aug/2026:14:04:35 +0000] "GET / HTTP/1.1" 502 157``
* **Kubernetes klog** ``E0812 14:05:41.008112       1 pod_workers.go:190] message``
* **Python tracebacks** — multi-line blocks are folded into a single ERROR
  entry whose message is the final exception line.

Design notes
------------
* Timestamps are normalized to *naive UTC* ``datetime`` objects so entries
  from different sources can be ordered on a single timeline.
* klog lines omit the year; the parser infers it from the most recent
  fully-dated entry seen in the same file (falling back to the current year).
* Unparseable lines never raise — they are counted and sampled so the CLI can
  report parse coverage honestly.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Iterable, Optional

__all__ = ["Severity", "LogEntry", "ParseResult", "LogParser"]


class Severity(IntEnum):
    """Normalized log severity, ordered so comparisons work (ERROR > INFO)."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def from_token(cls, token: str) -> "Severity":
        """Map a raw severity token from any supported format to a level.

        Unknown tokens default to ``INFO`` rather than raising, because a
        mis-labelled line should never abort an incident investigation.
        """
        mapping: dict[str, Severity] = {
            "TRACE": cls.DEBUG, "DEBUG": cls.DEBUG, "D": cls.DEBUG,
            "INFO": cls.INFO, "NOTICE": cls.INFO, "I": cls.INFO,
            "WARN": cls.WARNING, "WARNING": cls.WARNING, "W": cls.WARNING,
            "ERR": cls.ERROR, "ERROR": cls.ERROR, "E": cls.ERROR,
            "CRIT": cls.CRITICAL, "CRITICAL": cls.CRITICAL,
            "FATAL": cls.CRITICAL, "ALERT": cls.CRITICAL,
            "EMERG": cls.CRITICAL, "F": cls.CRITICAL,
        }
        return mapping.get(token.strip().upper(), cls.INFO)


@dataclass(slots=True)
class LogEntry:
    """A single normalized log event."""

    timestamp: Optional[datetime]
    severity: Severity
    source: str
    message: str
    raw: str
    line_number: int
    log_format: str
    status_code: Optional[int] = None

    def is_error(self) -> bool:
        """Return ``True`` for ERROR or CRITICAL entries."""
        return self.severity >= Severity.ERROR


@dataclass(slots=True)
class ParseResult:
    """Aggregate output of a parse run, including coverage statistics."""

    entries: list[LogEntry] = field(default_factory=list)
    total_lines: int = 0
    unparsed_count: int = 0
    unparsed_samples: list[tuple[int, str]] = field(default_factory=list)
    format_counts: Counter = field(default_factory=Counter)

    @property
    def parse_coverage(self) -> float:
        """Fraction of non-blank lines successfully attributed to an entry."""
        attributed = self.total_lines - self.unparsed_count
        return attributed / self.total_lines if self.total_lines else 0.0

    def error_entries(self) -> list[LogEntry]:
        """Return only ERROR/CRITICAL entries, in file order."""
        return [e for e in self.entries if e.is_error()]


# --------------------------------------------------------------------------
# Line-format regexes
# --------------------------------------------------------------------------

_APP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
    r"(?P<sev>[A-Z]{4,8})\s+"
    r"(?:\[(?P<src>[^\]]+)\]\s*)?"
    r"(?P<msg>.*)$"
)

_NGINX_ERROR_RE = re.compile(
    r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<sev>[a-z]+)\] (?P<msg>.*)$"
)

_NGINX_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) (?P<size>\d+|-)"
)

_KLOG_RE = re.compile(
    r"^(?P<sev>[IWEF])(?P<month>\d{2})(?P<day>\d{2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+\d+\s+"
    r"(?P<src>[\w.\-]+:\d+)\]\s+(?P<msg>.*)$"
)

_TRACEBACK_START = "Traceback (most recent call last):"


def _parse_app_timestamp(raw: str) -> Optional[datetime]:
    """Parse ``YYYY-MM-DD HH:MM:SS[,ffffff]`` (comma or dot fraction)."""
    cleaned = raw.replace(",", ".").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    return None


def _parse_access_timestamp(raw: str) -> Optional[datetime]:
    """Parse the CLF timestamp ``12/Aug/2026:14:04:35 +0000`` into naive UTC."""
    try:
        aware = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return aware.astimezone(timezone.utc).replace(tzinfo=None)


class LogParser:
    """Stateful parser that folds multi-line tracebacks and infers klog years.

    Usage::

        result = LogParser().parse_file("sample_logs/incident_001.log")
        for entry in result.error_entries():
            print(entry.timestamp, entry.message)
    """

    MAX_UNPARSED_SAMPLES: int = 20

    def __init__(self) -> None:
        self._year_hint: int = datetime.now().year

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, path: str | Path) -> ParseResult:
        """Parse a log file from disk.

        Raises:
            FileNotFoundError: if ``path`` does not exist.
            IsADirectoryError: if ``path`` is a directory.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        if path.is_dir():
            raise IsADirectoryError(f"Expected a file, got a directory: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return self.parse_lines(handle)

    def parse_lines(self, lines: Iterable[str]) -> ParseResult:
        """Parse an iterable of raw log lines into a :class:`ParseResult`."""
        result = ParseResult()
        traceback_buffer: Optional[list[str]] = None
        traceback_start_line = 0

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip("\n")

            if traceback_buffer is not None:
                traceback_buffer.append(line)
                # The first non-indented line after the frames is the
                # exception itself (e.g. ``psycopg2.OperationalError: ...``).
                if line and not line[0].isspace():
                    result.entries.append(
                        self._build_traceback_entry(
                            traceback_buffer, traceback_start_line, result
                        )
                    )
                    result.format_counts["traceback"] += 1
                    result.total_lines += len(traceback_buffer)
                    traceback_buffer = None
                continue

            if line.startswith(_TRACEBACK_START):
                traceback_buffer = [line]
                traceback_start_line = line_number
                continue

            if not line.strip():
                continue

            result.total_lines += 1
            entry = self._parse_single_line(line, line_number)
            if entry is None:
                result.unparsed_count += 1
                if len(result.unparsed_samples) < self.MAX_UNPARSED_SAMPLES:
                    result.unparsed_samples.append((line_number, line))
            else:
                result.entries.append(entry)
                result.format_counts[entry.log_format] += 1

        # File ended mid-traceback: keep whatever we captured.
        if traceback_buffer:
            result.entries.append(
                self._build_traceback_entry(
                    traceback_buffer, traceback_start_line, result
                )
            )
            result.format_counts["traceback"] += 1
            result.total_lines += len(traceback_buffer)

        return result

    # ------------------------------------------------------------------
    # Per-format handlers
    # ------------------------------------------------------------------

    def _parse_single_line(self, line: str, line_number: int) -> Optional[LogEntry]:
        """Try each known format in order of specificity; return None on miss."""
        match = _APP_RE.match(line)
        if match:
            timestamp = _parse_app_timestamp(match["ts"])
            if timestamp:
                self._year_hint = timestamp.year
            return LogEntry(
                timestamp=timestamp,
                severity=Severity.from_token(match["sev"]),
                source=match["src"] or "app",
                message=match["msg"].strip(),
                raw=line,
                line_number=line_number,
                log_format="app",
            )

        match = _NGINX_ERROR_RE.match(line)
        if match:
            try:
                timestamp: Optional[datetime] = datetime.strptime(
                    match["ts"], "%Y/%m/%d %H:%M:%S"
                )
                self._year_hint = timestamp.year
            except ValueError:
                timestamp = None
            return LogEntry(
                timestamp=timestamp,
                severity=Severity.from_token(match["sev"]),
                source="nginx",
                message=match["msg"].strip(),
                raw=line,
                line_number=line_number,
                log_format="nginx-error",
            )

        match = _NGINX_ACCESS_RE.match(line)
        if match:
            status = int(match["status"])
            if status >= 500:
                severity = Severity.ERROR
            elif status >= 400:
                severity = Severity.WARNING
            else:
                severity = Severity.INFO
            timestamp = _parse_access_timestamp(match["ts"])
            if timestamp:
                self._year_hint = timestamp.year
            return LogEntry(
                timestamp=timestamp,
                severity=severity,
                source="nginx-access",
                message=f'{match["request"]} -> HTTP {status}',
                raw=line,
                line_number=line_number,
                log_format="nginx-access",
                status_code=status,
            )

        match = _KLOG_RE.match(line)
        if match:
            timestamp = self._parse_klog_timestamp(
                match["month"], match["day"], match["time"]
            )
            return LogEntry(
                timestamp=timestamp,
                severity=Severity.from_token(match["sev"]),
                source=f'k8s/{match["src"]}',
                message=match["msg"].strip(),
                raw=line,
                line_number=line_number,
                log_format="klog",
            )

        return None

    def _parse_klog_timestamp(
        self, month: str, day: str, time_part: str
    ) -> Optional[datetime]:
        """klog omits the year, so borrow it from the last dated entry seen."""
        candidate = f"{self._year_hint}-{month}-{day} {time_part}"
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(candidate, fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _build_traceback_entry(
        buffer: list[str], start_line: int, result: ParseResult
    ) -> LogEntry:
        """Fold a captured traceback into one ERROR entry.

        The timestamp and source are inherited from the immediately preceding
        entry (application loggers emit the "Unhandled exception" line right
        before dumping the traceback to stderr).
        """
        previous = result.entries[-1] if result.entries else None
        exception_line = buffer[-1].strip() if buffer else "Unknown exception"
        return LogEntry(
            timestamp=previous.timestamp if previous else None,
            severity=Severity.ERROR,
            source=previous.source if previous else "python",
            message=exception_line,
            raw="\n".join(buffer),
            line_number=start_line,
            log_format="traceback",
        )
