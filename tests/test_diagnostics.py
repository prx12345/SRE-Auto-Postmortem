"""Unit tests for sre_analyzer.diagnostics."""

from sre_analyzer.diagnostics import analyze
from sre_analyzer.log_parser import LogParser


def analyze_text(text: str):
    parser = LogParser()
    return analyze(parser.parse_lines(text.splitlines()), source_file="test.log")


def test_db_timeout_preferred_over_downstream_502s() -> None:
    text = "\n".join(
        [
            "2026-08-12 14:03:12,540 ERROR [db-pool] Failed to acquire connection: timed out after 5000ms",
            "2026-08-12 14:03:28,731 ERROR [db-pool] Failed to acquire connection: timed out after 5000ms",
            "2026-08-12 14:03:41,002 ERROR [db-pool] Failed to acquire connection: timed out after 5000ms",
            '10.0.1.21 - - [12/Aug/2026:14:04:35 +0000] "GET /a HTTP/1.1" 502 157 "-" "-"',
            '10.0.1.21 - - [12/Aug/2026:14:04:36 +0000] "GET /a HTTP/1.1" 502 157 "-" "-"',
            '10.0.1.21 - - [12/Aug/2026:14:04:37 +0000] "GET /a HTTP/1.1" 502 157 "-" "-"',
            '10.0.1.21 - - [12/Aug/2026:14:04:38 +0000] "GET /a HTTP/1.1" 502 157 "-" "-"',
        ]
    )
    report = analyze_text(text)
    assert report.root_cause is not None
    # Deeper layer wins even though the 502s are more numerous.
    assert report.root_cause.signature.sig_id == "db_connection_timeout"
    assert report.confidence == "High"  # cause precedes every shallower symptom
    assert report.failed_requests_5xx == 4


def test_memory_exhaustion_detected_as_root_cause() -> None:
    text = "\n".join(
        [
            "2026-08-12 09:00:01,000 ERROR [worker] MemoryError: Cannot allocate 512MB buffer",
            "2026-08-12 09:00:05,000 ERROR [worker] MemoryError: Cannot allocate 512MB buffer",
            "E0812 09:00:30.000000       1 kubelet.go:120] Pod worker-1 OOMKilled, restarting container",
        ]
    )
    report = analyze_text(text)
    assert report.root_cause is not None
    assert report.root_cause.signature.sig_id == "memory_exhaustion"


def test_no_errors_yields_no_root_cause() -> None:
    report = analyze_text("2026-08-12 09:00:01,000 INFO [app] all good")
    assert report.root_cause is None
    assert report.incident_start is None
    assert report.incident_severity.startswith("SEV-4")


def test_incident_window_and_timeline_metrics() -> None:
    text = "\n".join(
        [
            "2026-08-12 14:03:10,000 ERROR [db-pool] timed out after 5000ms",
            "2026-08-12 14:03:50,000 ERROR [db-pool] timed out after 5000ms",
            "2026-08-12 14:05:10,000 ERROR [db-pool] timed out after 5000ms",
        ]
    )
    report = analyze_text(text)
    assert report.incident_start is not None and report.incident_end is not None
    assert report.duration is not None
    assert report.duration.total_seconds() == 120
    # Two errors landed in the 14:03 bucket -> that is the peak minute.
    assert report.peak_minute is not None
    assert report.peak_minute[1] == 2
    assert len(report.error_timeline) == 2


def test_report_serializes_to_dict() -> None:
    report = analyze_text("2026-08-12 14:03:10,000 ERROR [db-pool] timed out after 5000ms")
    payload = report.to_dict()
    assert payload["root_cause"]["id"] == "db_connection_timeout"
    assert payload["total_entries"] == 1
    assert isinstance(payload["error_timeline"], list)
