"""End-to-end tests: sample log -> diagnostics -> Markdown post-mortem."""

from pathlib import Path

from sre_analyzer.diagnostics import analyze
from sre_analyzer.log_parser import LogParser
from sre_analyzer.postmortem_generator import render_markdown, write_postmortem

SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "incident_001.log"


def build_report():
    parse_result = LogParser().parse_file(SAMPLE_LOG)
    return analyze(parse_result, source_file=str(SAMPLE_LOG))


def test_sample_incident_diagnosed_as_db_timeout() -> None:
    report = build_report()
    assert report.root_cause is not None
    assert report.root_cause.signature.sig_id == "db_connection_timeout"
    assert report.confidence == "High"
    assert report.failed_requests_5xx >= 10
    # All four line formats plus folded tracebacks should be recognized.
    for expected_format in ("app", "nginx-error", "nginx-access", "klog", "traceback"):
        assert expected_format in report.format_counts, expected_format


def test_rendered_markdown_contains_required_sections() -> None:
    markdown = render_markdown(build_report())
    for heading in (
        "# Post-Mortem:",
        "## 1. Incident Summary",
        "## 2. Impact",
        "## 3. Error-Rate Timeline",
        "## 4. Timeline of Events",
        "## 5. Root Cause Analysis",
        "## 7. Action Items",
        "## 8. Lessons Learned",
    ):
        assert heading in markdown, f"missing section: {heading}"
    assert "blameless" in markdown.lower()
    assert "- [ ]" in markdown  # actionable checkboxes


def test_write_postmortem_creates_file(tmp_path) -> None:
    output = tmp_path / "reports" / "postmortem.md"
    written = write_postmortem(build_report(), output)
    assert written.exists()
    assert written.read_text(encoding="utf-8").startswith("# Post-Mortem:")
