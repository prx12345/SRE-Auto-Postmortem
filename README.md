# SRE Log Analyzer & Post-Mortem Generator

A command-line tool that reads a raw incident log (Nginx, application logs, Kubernetes events, and Python tracebacks all mixed together), identifies the most likely root cause, and writes a first draft of a blameless post-mortem in Markdown.

Runs on **Python 3.10+** with no external dependencies. Clone it and run it.

---

## Why

The worst part of an incident is usually after it is over. You end up with four or five log sources, each with its own timestamp format and severity labels, and you have to piece the timeline together by hand before you can even start writing the post-mortem.

The other problem is that the loudest signal in the logs is almost never the actual cause. If the database stalls for four minutes, you might get six timeout errors from the database layer and a hundred 502 errors at the edge. Searching for the most common error often leads to blaming Nginx for an issue that originated two layers below it.

This tool automates the initial diagnostic process:
- Parses heterogeneous logs into a single UTC timeline.
- Matches entries against a library of known failure signatures.
- Ranks the most probable root cause using layer depth and temporal ordering.
- Generates a structured draft post-mortem report.

You retain ownership of the narrative and final review, avoiding the need to start documentation from a blank page.

---

## Quick Start

```bash
git clone https://github.com/princeraj/sre-log-analyzer.git
cd sre-log-analyzer
python main.py --log-file sample_logs/incident_001.log
cat postmortem.md
```

The bundled sample log simulates a database connection timeout that cascades into a 502 storm and failing readiness probes. Running the tool outputs:

```text
Parsed entries  : 52 (100.0% line coverage, 0 unparsed)
Incident window : 14:03:12 -> 14:07:21 UTC
Severity        : SEV-2
Root cause      : Database connection timeout [confidence: High]
5xx failures    : 16
```

### CLI Options

```text
--log-file PATH    Log file to analyze (required)
-o, --output PATH  Where to write the report (default: postmortem.md)
--json PATH        Emit diagnostic metrics as machine-readable JSON
-q, --quiet        Suppress console output summary
```

You can also run `pip install -e .` to enable the `sre-analyze` command directly.

---

## How Root Cause Ranking Works

Every failure signature in the catalog (database timeouts, OOM kills, pool exhaustion, upstream failures, 5xx cascades, failing probes, DNS, disk saturation, deadlocks) is mapped to a specific stack layer:

| Layer | Classification | Signatures |
| :---: | :--- | :--- |
| **0** | Infrastructure | OOM kills, disk full, DNS failures |
| **1** | Datastore | Connection timeouts, transaction deadlocks |
| **2** | Application | Pool exhaustion, unhandled exceptions |
| **3** | Edge / Ingress | 502 cascades, upstream timeouts, Kubernetes probe failures |

When multiple signatures match, the deepest layer takes priority (e.g., a database timeout explains a 502 storm; the reverse is structurally impossible). Ties are resolved by weighted score and earliest occurrence.

### Causal Confidence Verification
The engine validates causal precedence: if the identified root cause appears in logs prior to shallower downstream symptoms, confidence is graded as **High**. Otherwise, confidence degrades to **Medium** or **Low**. The report includes the chronological failure cascade and supporting log lines to allow full auditing of the diagnostic chain.

To add new failure modes, append a `FailureSignature` entry inside `src/sre_analyzer/diagnostics.py` with the corresponding regex patterns, layer depth, weight, and remediation action items.

---

## Repository Structure

```text
sre-log-analyzer/
├── main.py                     # CLI entry point (runs standalone)
├── src/sre_analyzer/
│   ├── log_parser.py           # Multi-format regex dispatch, folds tracebacks, normalizes UTC
│   ├── diagnostics.py          # Bucketing, incident window detection, signature ranking
│   ├── postmortem_generator.py # Renders Markdown post-mortem document
│   └── main.py                 # Argparse CLI configuration
├── tests/                      # Unit and end-to-end test suite
├── sample_logs/
│   └── incident_001.log        # Sample multi-format cascade incident
└── requirements.txt
```

### Log Parsing Specifications
- **Kubernetes Logs (`klog`):** Lacks explicit year notation; inferred from surrounding file context.
- **Access Logs:** Timezone offsets are converted to naive UTC to ensure cross-source timeline ordering.
- **Python Tracebacks:** Multi-line stack traces are folded into single `ERROR` events inheriting the primary timestamp.
- **Unparsed Lines:** Non-matching lines do not halt execution; overall parse coverage is calculated and declared in the report.

### Running Tests

```bash
pip install pytest
python -m pytest
```

---

## About This Project

Built as an SRE and incident analysis project focused on encoding realistic operational reasoning: failure cascades propagate up the stack and amplify in volume, making error frequency an inaccurate primary signal compared to stack depth and temporal order. Every diagnostic deduction remains rule-based and traceable to specific log lines.

**License:** MIT
