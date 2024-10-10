"""Zero-install entry point.

Lets the tool run straight from a fresh clone with no packaging step:

    python main.py --log-file sample_logs/incident_001.log

For an installed console script instead, run ``pip install -e .`` and use
``sre-analyze``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sre_analyzer.main import main  # noqa: E402  (path bootstrap must run first)

if __name__ == "__main__":
    raise SystemExit(main())
