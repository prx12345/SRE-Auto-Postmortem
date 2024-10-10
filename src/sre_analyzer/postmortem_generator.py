"""Render a :class:`~sre_analyzer.diagnostics.DiagnosticReport` as a blameless
Markdown post-mortem.

The output follows the standard SRE post-mortem shape (summary → impact →
timeline → root cause → action items) and is written as a *draft* for a human
to review: an automated tool can gather evidence and propose a causal story,
but the on-call engineer owns the final narrative.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .diagnostics import DiagnosticReport, SignatureMatch

__all__ = ["render_markdown", "write_postmortem"]

_LAYER_LABELS = {
    0: "Infrastructure",
    1: "Datastore",
    2: "Application",
    3: "Edge / Orchestration",
}


def _fmt_ts(value: Optional[datetime], with_date: bool = False) -> str:
    if value is None:
        return "unknown"
    return value.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def _fmt_duration(delta: Optional[timedelta]) -> str:
    if delta is None:
        return "unknown"
    total = int(delta.total_seconds())
    minutes, seconds = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _ascii_chart(timeline: list[tuple[datetime, int]], width: int = 40) -> str:
    """Render the per-minute error counts as a fixed-width ASCII bar chart."""
    if not timeline:
        return "(no error activity recorded)"
    peak = max(count for _, count in timeline)
    lines = []
    for minute, count in timeline:
        bar_length = max(1, round(width * count / peak)) if count else 0
        lines.append(f"{minute.strftime('%H:%M')} | {'█' * bar_length} {count}")
    return "\n".join(lines)


def _incident_id(report: DiagnosticReport) -> str:
    stem = Path(report.source_file).stem.upper().replace("_", "-")
    return f"INC-{stem}"


def _summary_paragraph(report: DiagnosticReport) -> str:
    if report.incident_start is None:
        return (
            "No error-level events were found in the analyzed log. "
            "This report documents the analysis for completeness."
        )
    date = report.incident_start.strftime("%Y-%m-%d")
    window = (
        f"between **{_fmt_ts(report.incident_start)}** and "
        f"**{_fmt_ts(report.incident_end)}** UTC"
    )
    error_total = report.severity_counts.get("ERROR", 0) + report.severity_counts.get(
        "CRITICAL", 0
    )
    parts = [
        f"On **{date}**, {window} "
        f"({_fmt_duration(report.duration)}), the service emitted "
        f"**{error_total} error-level events** across "
        f"{len(report.format_counts)} log sources."
    ]
    if report.failed_requests_5xx:
        parts.append(
            f"**{report.failed_requests_5xx} client requests failed with HTTP 5xx** "
            "responses at the edge during the window."
        )
    if report.root_cause is not None:
        parts.append(
            f"Automated analysis attributes the incident to "
            f"**{report.root_cause.signature.name.lower()}** "
            f"(confidence: {report.confidence.lower()}), with "
            f"{len(report.symptoms)} downstream failure signature"
            f"{'s' if len(report.symptoms) != 1 else ''} observed as symptoms."
        )
    else:
        parts.append(
            "No known failure signature matched — manual investigation is required."
        )
    return " ".join(parts)


def _cascade_section(report: DiagnosticReport) -> str:
    """Describe the propagation chain in first-occurrence order."""
    timed = [m for m in report.matches if m.first_seen is not None]
    if len(timed) < 2:
        return "_Not enough matched signatures to reconstruct a cascade._"
    steps = []
    for index, match in enumerate(timed, start=1):
        layer = _LAYER_LABELS.get(match.signature.layer, "Unknown")
        steps.append(
            f"{index}. `{_fmt_ts(match.first_seen)}` — **{match.signature.name}** "
            f"({layer} layer, {match.count}×)"
        )
    return "\n".join(steps)


def _evidence_block(match: SignatureMatch) -> str:
    samples = "\n".join(match.samples) if match.samples else "(no samples captured)"
    return f"```text\n{samples}\n```"


def _action_items(report: DiagnosticReport) -> str:
    lines: list[str] = []
    if report.root_cause is not None:
        for item in report.root_cause.signature.remediation:
            lines.append(f"- [ ] **[P0]** {item}")
    seen: set[str] = set()
    for symptom in report.symptoms:
        for item in symptom.signature.remediation:
            if item not in seen:
                seen.add(item)
                lines.append(f"- [ ] **[P1]** {item}")
    lines.append(
        "- [ ] **[P2]** Run a game-day exercise reproducing this failure mode "
        "to validate the fixes above."
    )
    lines.append(
        "- [ ] **[P2]** Review whether detection could have paged on the "
        "earliest warning signal in the timeline rather than on user-visible errors."
    )
    return "\n".join(lines)


def render_markdown(report: DiagnosticReport) -> str:
    """Build the complete post-mortem document as a Markdown string."""
    title = (
        report.root_cause.signature.name
        if report.root_cause
        else "Unclassified Incident"
    )
    root = report.root_cause

    sections: list[str] = []

    sections.append(f"# Post-Mortem: {title}")
    sections.append(
        "> **Status:** Draft — auto-generated by "
        "[SRE Log Analyzer](https://github.com/) and pending human review.\n"
        ">\n"
        "> This is a **blameless** post-mortem: it examines systemic and "
        "process factors, never individual fault."
    )

    sections.append(
        "\n".join(
            [
                "| Field | Value |",
                "| --- | --- |",
                f"| Incident ID | `{_incident_id(report)}` |",
                f"| Source log | `{report.source_file}` |",
                f"| Incident window (UTC) | {_fmt_ts(report.incident_start, with_date=True)}"
                f" → {_fmt_ts(report.incident_end, with_date=True)} |",
                f"| Duration | {_fmt_duration(report.duration)} |",
                f"| Severity | **{report.incident_severity}** |",
                f"| Root cause (automated) | {title} |",
                f"| Confidence | {report.confidence} |",
                f"| Report generated | {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')} |",
            ]
        )
    )

    sections.append("## 1. Incident Summary\n\n" + _summary_paragraph(report))

    impact_lines = [
        f"- **{report.failed_requests_5xx}** client-facing requests failed with "
        "HTTP 5xx at the edge.",
        f"- **{report.severity_counts.get('ERROR', 0)}** ERROR and "
        f"**{report.severity_counts.get('CRITICAL', 0)}** CRITICAL events logged "
        f"across sources: {', '.join(sorted(report.format_counts)) or 'n/a'}.",
    ]
    if report.peak_minute:
        impact_lines.append(
            f"- Peak failure rate: **{report.peak_minute[1]} errors/minute** "
            f"at {_fmt_ts(report.peak_minute[0])}."
        )
    sections.append("## 2. Impact\n\n" + "\n".join(impact_lines))

    sections.append(
        "## 3. Error-Rate Timeline\n\n"
        "Errors per minute (all sources):\n\n"
        f"```text\n{_ascii_chart(report.error_timeline)}\n```"
    )

    timeline_rows = ["| Time (UTC) | Event |", "| --- | --- |"]
    for timestamp, description in report.key_events:
        timeline_rows.append(f"| {_fmt_ts(timestamp)} | {description} |")
    sections.append("## 4. Timeline of Events\n\n" + "\n".join(timeline_rows))

    if root is not None:
        layer = _LAYER_LABELS.get(root.signature.layer, "Unknown")
        rca = [
            f"**Identified root cause:** {root.signature.name} "
            f"({layer} layer) — confidence **{report.confidence}**.",
            "",
            root.signature.description,
            "",
            f"The signature first fired at `{_fmt_ts(root.first_seen)}` and "
            f"recurred **{root.count}** times. Every shallower failure signature "
            "in this incident first appeared *after* this one, which supports "
            "the causal ordering below."
            if report.confidence == "High"
            else f"The signature first fired at `{_fmt_ts(root.first_seen)}` and "
            f"recurred **{root.count}** times.",
            "",
            "**Evidence (sample log lines):**",
            "",
            _evidence_block(root),
            "",
            "### Failure cascade (first occurrence of each signature)",
            "",
            _cascade_section(report),
        ]
        sections.append("## 5. Root Cause Analysis\n\n" + "\n".join(rca))
    else:
        sections.append(
            "## 5. Root Cause Analysis\n\n"
            "No known failure signature matched the log contents. "
            "Recommended next step: inspect the highest-severity entries manually "
            "and extend the signature library once the failure mode is understood."
        )

    if report.symptoms:
        factor_lines = []
        for symptom in report.symptoms:
            factor_lines.append(
                f"- **{symptom.signature.name}** "
                f"({symptom.count}×, first seen {_fmt_ts(symptom.first_seen)}): "
                f"{symptom.signature.description}"
            )
        sections.append(
            "## 6. Contributing Factors & Downstream Symptoms\n\n"
            + "\n".join(factor_lines)
        )
    else:
        sections.append(
            "## 6. Contributing Factors & Downstream Symptoms\n\n"
            "_No secondary failure signatures were detected._"
        )

    sections.append("## 7. Action Items\n\n" + _action_items(report))

    sections.append(
        "## 8. Lessons Learned\n\n"
        "- The earliest warning signal preceded user-visible impact — detection "
        "and alerting should target leading indicators, not just 5xx rates.\n"
        "- Failures propagated across layers "
        "(datastore → application → edge); resilience mechanisms (timeouts, "
        "circuit breakers, load shedding) should be validated at each boundary.\n\n"
        "---\n\n"
        "*Generated automatically. Parse coverage: "
        f"{report.parse_coverage:.1%} of {report.total_lines} log lines "
        f"({report.unparsed_count} unparsed). "
        "Numbers in this report are traceable to specific log lines; verify the "
        "narrative before publishing.*"
    )

    return "\n\n".join(sections) + "\n"


def write_postmortem(report: DiagnosticReport, output_path: str | Path) -> Path:
    """Render the report and write it to ``output_path``.

    Parent directories are created if needed. Returns the resolved path.

    Raises:
        OSError: if the destination is not writable.
    """
    path = Path(output_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(report), encoding="utf-8")
    return path.resolve()
