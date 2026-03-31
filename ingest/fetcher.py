"""
fetcher.py

Unified fetcher: switches between live AWS and mock data.
This is the single entry point the rest of the pipeline uses.

CONCEPT: Strategy pattern
The pipeline doesn't care WHERE data comes from.
It just calls fetch_alerts(mode="live") or fetch_alerts(mode="mock").
This makes the system testable (always works with mock)
and production-ready (just switch mode).
"""

import json
import sys
from pathlib import Path
from typing import Literal

sys.path.insert(0, str(Path(__file__).parent.parent))
from ingest.normalizer import NormalizedAlert, normalize_all


def fetch_alerts(
    mode:               Literal["live", "mock"] = "mock",
    region:             str   = "eu-central-1",
    severity_threshold: float = 4.0,
    hours_back:         int   = 24,
    mock_file:          str   = "ingest/mock_alerts.json"
) -> list[NormalizedAlert]:
    """
    Main pipeline entry point.

    mode="mock"  → load from mock_alerts.json (dev/demo/CI)
    mode="live"  → pull from real AWS GuardDuty (production)

    Either way, returns the same list[NormalizedAlert] —
    the rest of the pipeline is completely unchanged.
    """
    if mode == "mock":
        print(f"[fetcher] Mode: MOCK — loading {mock_file}")
        raw = json.loads(Path(mock_file).read_text())

    elif mode == "live":
        print(f"[fetcher] Mode: LIVE — pulling from AWS "
              f"({region}, severity>={severity_threshold}, "
              f"last {hours_back}h)")
        from ingest.guardduty_fetcher import fetch_guardduty_findings
        raw = fetch_guardduty_findings(
            region=region,
            severity_threshold=severity_threshold,
            hours_back=hours_back
        )

        # Fallback to mock if AWS returns nothing
        # (common in quiet lab environments)
        if not raw:
            print("[fetcher] No live findings — falling back to mock data")
            raw = json.loads(Path(mock_file).read_text())

    else:
        raise ValueError(f"Unknown mode: {mode}. Use 'live' or 'mock'.")

    return normalize_all(raw)