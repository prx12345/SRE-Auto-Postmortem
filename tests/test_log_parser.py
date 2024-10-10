"""Unit tests for sre_analyzer.log_parser."""

from datetime import datetime

import pytest

from sre_analyzer.log_parser import LogParser, Severity


def parse(text: str):
    return LogParser().parse_lines(text.splitlines())


def test_parses_app_log_line() -> None:
    result = parse("2026-08-12 14:03:12,540 ERROR [db-pool] Failed to acquire connection")
    assert len(result.entries) == 1
    entry = result.entries[0]
    assert entry.timestamp == datetime(2026, 8, 12, 14, 3, 12, 540000)
    assert entry.severity is Severity.ERROR
    assert entry.source == "db-pool"
    assert entry.log_format == "app"


def test_parses_nginx_error_line() -> None:
    line = (
        "2026/08/12 14:04:31 [error] 412#412: *90211 upstream timed out "
        "(110: Connection timed out) while reading response header from upstream"
    )
    result = parse(line)
    entry = result.entries[0]
    assert entry.severity is Severity.ERROR
    assert entry.source == "nginx"
    assert entry.timestamp == datetime(2026, 8, 12, 14, 4, 31)


def test_parses_nginx_access_line_and_maps_5xx_to_error() -> None:
    line = '10.0.1.21 - - [12/Aug/2026:14:04:35 +0000] "GET /api/v1/orders HTTP/1.1" 502 157 "-" "curl/8.0"'
    result = parse(line)
    entry = result.entries[0]
    assert entry.status_code == 502
    assert entry.severity is Severity.ERROR
    assert entry.timestamp == datetime(2026, 8, 12, 14, 4, 35)


def test_access_timestamp_normalized_to_utc() -> None:
    line = '10.0.1.21 - - [12/Aug/2026:16:04:35 +0200] "GET / HTTP/1.1" 200 10 "-" "-"'
    result = parse(line)
    assert result.entries[0].timestamp == datetime(2026, 8, 12, 14, 4, 35)


def test_parses_klog_line_with_year_inferred_from_earlier_entry() -> None:
    text = (
        "2026-08-12 14:00:00,000 INFO [app] warm-up\n"
        "E0812 14:05:52.008112       1 pod_workers.go:190] Error syncing pod payments-api"
    )
    result = parse(text)
    klog_entry = result.entries[1]
    assert klog_entry.severity is Severity.ERROR
    assert klog_entry.timestamp is not None
    assert klog_entry.timestamp.year == 2026
    assert klog_entry.source == "k8s/pod_workers.go:190"


def test_folds_traceback_into_single_error_entry() -> None:
    text = (
        "2026-08-12 14:03:12,544 ERROR [payments-api] Unhandled exception\n"
        "Traceback (most recent call last):\n"
        '  File "/app/db.py", line 88, in acquire\n'
        "    conn = self._pool.getconn(timeout=5.0)\n"
        "psycopg2.OperationalError: timeout expired\n"
        "2026-08-12 14:03:20,118 ERROR [db-pool] connection pool exhausted"
    )
    result = parse(text)
    formats = [entry.log_format for entry in result.entries]
    assert formats == ["app", "traceback", "app"]
    traceback_entry = result.entries[1]
    assert traceback_entry.message == "psycopg2.OperationalError: timeout expired"
    assert traceback_entry.severity is Severity.ERROR
    # Timestamp inherited from the preceding "Unhandled exception" line.
    assert traceback_entry.timestamp == result.entries[0].timestamp
    assert "Traceback (most recent call last):" in traceback_entry.raw


def test_unparsed_lines_are_counted_not_raised() -> None:
    result = parse("this line matches no known format\n2026-08-12 14:00:00 INFO ok")
    assert result.unparsed_count == 1
    assert len(result.entries) == 1
    assert 0 < result.parse_coverage < 1


def test_severity_token_normalization() -> None:
    assert Severity.from_token("warn") is Severity.WARNING
    assert Severity.from_token("EMERG") is Severity.CRITICAL
    assert Severity.from_token("weird-token") is Severity.INFO


def test_parse_file_missing_path_raises(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        LogParser().parse_file(tmp_path / "does-not-exist.log")
