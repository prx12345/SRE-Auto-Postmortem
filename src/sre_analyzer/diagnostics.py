"""Incident diagnostics: metrics, failure-signature matching, root-cause ranking.

The engine works in three passes over the normalized :class:`~sre_analyzer.log_parser.LogEntry`
stream:

1. **Metrics** — error frequency is bucketed per minute to find the incident
   window (first ERROR to last ERROR) and the peak error rate.
2. **Signature matching** — every entry is tested against a library of known
   failure signatures (database timeouts, OOM kills, gateway 502 cascades,
   failing health probes, ...). Each signature carries a *layer* describing
   how deep in the stack it lives:

   ========  =========================================
   Layer 0   Infrastructure (memory, disk, DNS)
   Layer 1   Datastore (DB timeouts, deadlocks)
   Layer 2   Application (pool exhaustion, exceptions)
   Layer 3   Edge / orchestration (502s, probe failures)
   ========  =========================================

3. **Root-cause ranking** — among matched signatures, the *deepest* layer wins
   (a database timeout explains a 502 storm; the reverse is not true). Ties
   break on weighted score, then on earliest first occurrence. Confidence is
   derived from causal ordering: if the chosen root cause fired *before*
   every shallower symptom, the causal story is consistent and confidence is
   high.

This is deliberately a transparent, rule-based system: every conclusion in the
generated post-mortem can be traced back to specific log lines.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from .log_parser import LogEntry, ParseResult, Severity

__all__ = [
    "FailureSignature",
    "SignatureMatch",
    "DiagnosticReport",
    "SIGNATURES",
    "analyze",
]


# --------------------------------------------------------------------------
# Failure-signature library
# --------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class FailureSignature:
    """A known failure mode, recognized by regex patterns and/or status class."""

    sig_id: str
    name: str
    layer: int
    weight: float
    description: str
    remediation: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...] = ()
    status_class: Optional[int] = None  # e.g. 5 matches any HTTP 5xx entry

    def matches(self, entry: LogEntry) -> bool:
        """Return ``True`` if this signature recognizes the entry."""
        if (
            self.status_class is not None
            and entry.status_code is not None
            and entry.status_code // 100 == self.status_class
        ):
            return True
        return any(pattern.search(entry.raw) for pattern in self.patterns)


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


SIGNATURES: tuple[FailureSignature, ...] = (
    FailureSignature(
        sig_id="memory_exhaustion",
        name="Memory exhaustion / OOM kill",
        layer=0,
        weight=3.0,
        description=(
            "A process exceeded available memory and was terminated (or began "
            "failing allocations). Typical of memory leaks or under-provisioned "
            "limits; downstream symptoms include restarts and request failures."
        ),
        remediation=(
            "Capture a heap profile and identify the allocation hot path.",
            "Review container memory limits and requests against real usage.",
            "Add alerting on RSS growth rate, not just absolute usage.",
        ),
        patterns=_compile(
            r"OOMKilled",
            r"oom-killer",
            r"\bMemoryError\b",
            r"Out of memory",
            r"Cannot allocate memory",
        ),
    ),
    FailureSignature(
        sig_id="disk_pressure",
        name="Disk exhaustion / filesystem pressure",
        layer=0,
        weight=3.0,
        description=(
            "The node ran out of disk or the filesystem became read-only, "
            "causing writes (logs, WAL, temp files) to fail."
        ),
        remediation=(
            "Add disk-usage alerting with predictive (rate-based) thresholds.",
            "Audit log rotation and temp-file cleanup on the affected nodes.",
        ),
        patterns=_compile(
            r"No space left on device",
            r"disk pressure",
            r"read-only file system",
        ),
    ),
    FailureSignature(
        sig_id="dns_resolution_failure",
        name="DNS resolution failure",
        layer=0,
        weight=2.5,
        description=(
            "Service names stopped resolving, breaking inter-service calls "
            "even though the services themselves were healthy."
        ),
        remediation=(
            "Check cluster DNS (CoreDNS/kube-dns) health and QPS limits.",
            "Add negative-caching and retry-with-backoff on resolution failures.",
        ),
        patterns=_compile(
            r"Temporary failure in name resolution",
            r"Name or service not known",
            r"NXDOMAIN",
            r"could not resolve host",
        ),
    ),
    FailureSignature(
        sig_id="db_connection_timeout",
        name="Database connection timeout",
        layer=1,
        weight=3.0,
        description=(
            "The application could not establish (or reuse) connections to the "
            "database within its timeout budget. Requests queued behind the "
            "stalled connections, exhausting worker capacity and cascading "
            "upward into gateway errors."
        ),
        remediation=(
            "Investigate database-side saturation at the incident start time "
            "(active connections, locks, IO wait, failover events).",
            "Add alerting on connection-acquisition latency (the leading "
            "indicator that preceded this incident) rather than on 5xx rate alone.",
            "Set aggressive connect timeouts with jittered retries so workers "
            "fail fast instead of queueing.",
            "Consider a circuit breaker between the API tier and the database "
            "to shed load during datastore degradation.",
        ),
        patterns=_compile(
            r"timeout expired",
            r"timed out after \d+",
            r"connection to server .* failed",
            r"could not connect to server",
            r"database .* timed out",
            r"Failed to acquire connection",
            r"psycopg2\.OperationalError",
        ),
    ),
    FailureSignature(
        sig_id="db_deadlock",
        name="Database deadlock / lock contention",
        layer=1,
        weight=2.5,
        description=(
            "Transactions blocked each other, causing queries to stall or be "
            "aborted by the lock manager."
        ),
        remediation=(
            "Identify the competing transactions and enforce consistent lock "
            "ordering.",
            "Shorten transaction scope; move slow work outside transactions.",
        ),
        patterns=_compile(
            r"deadlock detected",
            r"Lock wait timeout exceeded",
        ),
    ),
    FailureSignature(
        sig_id="connection_pool_exhaustion",
        name="Connection pool exhaustion",
        layer=2,
        weight=2.0,
        description=(
            "All pooled connections were in use and new requests queued. "
            "Usually a *symptom* of a slow dependency holding connections open "
            "rather than an independent fault."
        ),
        remediation=(
            "Alert on pool utilization (e.g. >80% in use) as an early-warning "
            "signal.",
            "Bound the pool wait queue so overload fails fast.",
        ),
        patterns=_compile(
            r"connection pool exhausted",
            r"\d+/\d+ connections in use",
            r"\bPoolError\b",
            r"\d+ requests waiting",
        ),
    ),
    FailureSignature(
        sig_id="unhandled_exception",
        name="Unhandled application exceptions",
        layer=2,
        weight=1.5,
        description=(
            "Requests terminated with uncaught exceptions, indicating the "
            "application lacked graceful degradation for a failing dependency."
        ),
        remediation=(
            "Wrap dependency calls with explicit exception handling and return "
            "meaningful 503s with Retry-After instead of stack traces.",
        ),
        patterns=_compile(
            r"Traceback \(most recent call last\)",
            r"Unhandled exception",
            r"Uncaught exception",
        ),
    ),
    FailureSignature(
        sig_id="upstream_gateway_failure",
        name="Reverse-proxy upstream failures",
        layer=3,
        weight=1.5,
        description=(
            "Nginx could not get timely responses from its upstream "
            "application servers — the edge-visible face of a deeper failure."
        ),
        remediation=(
            "Serve a cached/static degradation page for read endpoints during "
            "upstream outages.",
            "Tune proxy_read_timeout and retry policy to avoid retry storms.",
        ),
        patterns=_compile(
            r"upstream timed out",
            r"connect\(\) failed .* while connecting to upstream",
            r"no live upstreams",
            r"while reading response header from upstream",
        ),
    ),
    FailureSignature(
        sig_id="http_5xx_cascade",
        name="HTTP 5xx error cascade",
        layer=3,
        weight=1.0,
        description=(
            "Clients received server errors (502/503/504) at the edge — the "
            "user-visible impact of the incident."
        ),
        remediation=(
            "Confirm client-side retry behaviour did not amplify load during "
            "the outage.",
        ),
        status_class=5,
        patterns=_compile(r'HTTP/\d\.\d" 50\d '),
    ),
    FailureSignature(
        sig_id="failing_health_probes",
        name="Failing Kubernetes health probes",
        layer=3,
        weight=1.0,
        description=(
            "Readiness/liveness probes failed, so the orchestrator pulled pods "
            "from rotation — shrinking capacity exactly when load was queueing."
        ),
        remediation=(
            "Ensure readiness probes reflect dependency health without causing "
            "full-fleet ejection during shared-dependency outages.",
        ),
        patterns=_compile(
            r"Readiness probe failed",
            r"Liveness probe failed",
            r"Error syncing pod",
        ),
    ),
)


# --------------------------------------------------------------------------
# Match & report structures
# --------------------------------------------------------------------------

@dataclass(slots=True)
class SignatureMatch:
    """Aggregated evidence that one failure signature fired during the incident."""

    signature: FailureSignature
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    samples: list[str] = field(default_factory=list)

    MAX_SAMPLES = 3

    def record(self, entry: LogEntry) -> None:
        """Fold one matching entry into this aggregate."""
        self.count += 1
        if entry.timestamp is not None:
            if self.first_seen is None or entry.timestamp < self.first_seen:
                self.first_seen = entry.timestamp
            if self.last_seen is None or entry.timestamp > self.last_seen:
                self.last_seen = entry.timestamp
        if len(self.samples) < self.MAX_SAMPLES:
            first_line = entry.raw.splitlines()[0] if entry.raw else entry.message
            self.samples.append(first_line[:200])

    @property
    def score(self) -> float:
        """Weighted evidence score (frequency dampened by a soft cap)."""
        return self.signature.weight * min(self.count, 50)


@dataclass(slots=True)
class DiagnosticReport:
    """Everything the post-mortem generator needs, in one structure."""

    source_file: str
    generated_at: datetime
    total_entries: int
    total_lines: int
    unparsed_count: int
    parse_coverage: float
    severity_counts: dict[str, int]
    format_counts: dict[str, int]
    incident_start: Optional[datetime]
    incident_end: Optional[datetime]
    error_timeline: list[tuple[datetime, int]]
    peak_minute: Optional[tuple[datetime, int]]
    failed_requests_5xx: int
    matches: list[SignatureMatch]
    root_cause: Optional[SignatureMatch]
    confidence: str
    incident_severity: str
    key_events: list[tuple[datetime, str]]

    @property
    def duration(self) -> Optional[timedelta]:
        """Length of the incident window, if one was detected."""
        if self.incident_start and self.incident_end:
            return self.incident_end - self.incident_start
        return None

    @property
    def symptoms(self) -> list[SignatureMatch]:
        """Matched signatures other than the chosen root cause."""
        return [m for m in self.matches if m is not self.root_cause]

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable view of the report (for ``--json`` output)."""

        def _ts(value: Optional[datetime]) -> Optional[str]:
            return value.isoformat(sep=" ") if value else None

        return {
            "source_file": self.source_file,
            "generated_at": _ts(self.generated_at),
            "total_entries": self.total_entries,
            "total_lines": self.total_lines,
            "unparsed_count": self.unparsed_count,
            "parse_coverage": round(self.parse_coverage, 4),
            "severity_counts": self.severity_counts,
            "format_counts": self.format_counts,
            "incident_start": _ts(self.incident_start),
            "incident_end": _ts(self.incident_end),
            "duration_seconds": (
                self.duration.total_seconds() if self.duration else None
            ),
            "incident_severity": self.incident_severity,
            "failed_requests_5xx": self.failed_requests_5xx,
            "peak_minute": (
                {"minute": _ts(self.peak_minute[0]), "errors": self.peak_minute[1]}
                if self.peak_minute
                else None
            ),
            "error_timeline": [
                {"minute": _ts(minute), "errors": count}
                for minute, count in self.error_timeline
            ],
            "root_cause": (
                {
                    "id": self.root_cause.signature.sig_id,
                    "name": self.root_cause.signature.name,
                    "layer": self.root_cause.signature.layer,
                    "occurrences": self.root_cause.count,
                    "first_seen": _ts(self.root_cause.first_seen),
                    "confidence": self.confidence,
                }
                if self.root_cause
                else None
            ),
            "matched_signatures": [
                {
                    "id": m.signature.sig_id,
                    "name": m.signature.name,
                    "layer": m.signature.layer,
                    "occurrences": m.count,
                    "first_seen": _ts(m.first_seen),
                    "last_seen": _ts(m.last_seen),
                    "samples": m.samples,
                }
                for m in self.matches
            ],
        }


# --------------------------------------------------------------------------
# Analysis passes
# --------------------------------------------------------------------------

def _bucket_errors_by_minute(entries: list[LogEntry]) -> list[tuple[datetime, int]]:
    """Count ERROR+ entries per minute, returned in chronological order."""
    buckets: Counter[datetime] = Counter()
    for entry in entries:
        if entry.is_error() and entry.timestamp is not None:
            buckets[entry.timestamp.replace(second=0, microsecond=0)] += 1
    return sorted(buckets.items())


def _match_signatures(entries: list[LogEntry]) -> list[SignatureMatch]:
    """Run every entry through the signature library and aggregate hits."""
    hits: dict[str, SignatureMatch] = {}
    for entry in entries:
        for signature in SIGNATURES:
            if signature.matches(entry):
                match = hits.setdefault(
                    signature.sig_id, SignatureMatch(signature=signature)
                )
                match.record(entry)
    # Present matches in causal (chronological) order where possible.
    return sorted(
        hits.values(),
        key=lambda m: (m.first_seen or datetime.max, m.signature.layer),
    )


def _select_root_cause(
    matches: list[SignatureMatch],
) -> tuple[Optional[SignatureMatch], str]:
    """Pick the most likely root cause and rate confidence in the choice.

    Selection: deepest layer first, then highest weighted score, then earliest
    first occurrence. Confidence: high when the chosen cause temporally
    precedes every shallower symptom (a consistent causal chain).
    """
    if not matches:
        return None, "None"

    root = min(
        matches,
        key=lambda m: (
            m.signature.layer,
            -m.score,
            m.first_seen or datetime.max,
        ),
    )

    shallower = [m for m in matches if m.signature.layer > root.signature.layer]
    causally_consistent = all(
        root.first_seen is not None
        and m.first_seen is not None
        and root.first_seen <= m.first_seen
        for m in shallower
    )

    if root.count >= 3 and (not shallower or causally_consistent):
        confidence = "High"
    elif root.count >= 2:
        confidence = "Medium"
    else:
        confidence = "Low"
    return root, confidence


def _classify_incident_severity(
    peak_minute: Optional[tuple[datetime, int]], severity_counts: dict[str, int]
) -> str:
    """Rough SEV classification from blast-radius heuristics."""
    peak = peak_minute[1] if peak_minute else 0
    if severity_counts.get("CRITICAL", 0) > 0 or peak >= 20:
        return "SEV-1"
    if peak >= 5:
        return "SEV-2"
    if peak > 0:
        return "SEV-3"
    return "SEV-4 (no error spike detected)"


def _build_key_events(
    entries: list[LogEntry],
    matches: list[SignatureMatch],
    incident_start: Optional[datetime],
    incident_end: Optional[datetime],
    peak_minute: Optional[tuple[datetime, int]],
) -> list[tuple[datetime, str]]:
    """Assemble the human-readable timeline for the post-mortem."""
    events: list[tuple[datetime, str]] = []

    first_warning = next(
        (
            e
            for e in entries
            if e.severity == Severity.WARNING and e.timestamp is not None
        ),
        None,
    )
    if first_warning is not None and (
        incident_start is None or first_warning.timestamp < incident_start
    ):
        events.append(
            (
                first_warning.timestamp,
                f"⚠️ Early warning signal: `{first_warning.message[:120]}`",
            )
        )

    if incident_start:
        events.append((incident_start, "🔴 Incident begins — first error observed."))

    for match in matches:
        if match.first_seen is not None:
            events.append(
                (
                    match.first_seen,
                    f"First **{match.signature.name}** event "
                    f"({match.count} occurrence{'s' if match.count != 1 else ''} total).",
                )
            )

    if peak_minute:
        events.append(
            (
                peak_minute[0],
                f"📈 Error rate peaks at **{peak_minute[1]} errors/minute**.",
            )
        )

    if incident_end:
        events.append(
            (incident_end, "🟢 Last error observed — system begins recovering.")
        )

    return sorted(events, key=lambda item: item[0])


def analyze(parse_result: ParseResult, source_file: str) -> DiagnosticReport:
    """Run the full diagnostic pipeline over parsed log entries.

    Args:
        parse_result: Output of :meth:`LogParser.parse_file`.
        source_file: Path of the analyzed file (used for report metadata).

    Returns:
        A fully-populated :class:`DiagnosticReport`. If the log contains no
        errors, ``root_cause`` is ``None`` and severity reflects that.
    """
    entries = parse_result.entries
    error_entries = [e for e in entries if e.is_error() and e.timestamp is not None]

    severity_counts = Counter(entry.severity.name for entry in entries)
    error_timeline = _bucket_errors_by_minute(entries)
    peak_minute = max(error_timeline, key=lambda item: item[1], default=None)

    incident_start = min((e.timestamp for e in error_entries), default=None)
    incident_end = max((e.timestamp for e in error_entries), default=None)

    failed_requests_5xx = sum(
        1
        for entry in entries
        if entry.status_code is not None and entry.status_code >= 500
    )

    matches = _match_signatures(entries)
    root_cause, confidence = _select_root_cause(matches)

    return DiagnosticReport(
        source_file=source_file,
        generated_at=datetime.now(),
        total_entries=len(entries),
        total_lines=parse_result.total_lines,
        unparsed_count=parse_result.unparsed_count,
        parse_coverage=parse_result.parse_coverage,
        severity_counts=dict(severity_counts),
        format_counts=dict(parse_result.format_counts),
        incident_start=incident_start,
        incident_end=incident_end,
        error_timeline=error_timeline,
        peak_minute=peak_minute,
        failed_requests_5xx=failed_requests_5xx,
        matches=matches,
        root_cause=root_cause,
        confidence=confidence,
        incident_severity=_classify_incident_severity(peak_minute, dict(severity_counts)),
        key_events=_build_key_events(
            entries, matches, incident_start, incident_end, peak_minute
        ),
    )
