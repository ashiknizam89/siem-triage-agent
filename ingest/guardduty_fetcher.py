"""
guardduty_fetcher.py

Responsibility: Pull real GuardDuty findings from AWS
and return them in the same format as mock_alerts.json —
so the normalizer works identically on real or mock data.

Key concepts:
- Boto3 client vs resource
- Pagination with get_paginator()
- FindingCriteria for filtering
- Batching get_findings() calls (max 50 IDs per call)
- Least-privilege IAM note
"""

import boto3
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))


def get_detector_id(region: str) -> str:
    """
    CONCEPT: Boto3 client initialisation
    boto3.client() creates a service client.
    It reads credentials from ~/.aws/credentials automatically.
    region_name tells it which AWS region to talk to.

    GuardDuty has one "detector" per region per account.
    The detector ID is the handle for all other API calls.
    """
    client = boto3.client("guardduty", region_name=region)
    response = client.list_detectors()
    detectors = response.get("DetectorIds", [])

    if not detectors:
        raise RuntimeError(
            f"No GuardDuty detector found in {region}. "
            "Enable GuardDuty in the AWS console first."
        )

    detector_id = detectors[0]
    print(f"[guardduty] Detector ID: {detector_id} (region: {region})")
    return detector_id


def list_finding_ids(
    client,
    detector_id: str,
    severity_threshold: float = 4.0,
    hours_back: int = 24,
    max_findings: int = 50
) -> list[str]:
    """
    CONCEPT: FindingCriteria — server-side filtering
    Instead of pulling ALL findings and filtering in Python,
    we push the filter to AWS. This is called server-side
    filtering — it reduces data transfer and API cost.

    We filter by:
    - severity >= threshold (skip LOW noise by default)
    - updatedAt within the last N hours (recent findings only)

    CONCEPT: Paginator
    list_findings is paginated — max 50 IDs per page.
    The paginator handles NextToken automatically.
    We collect all IDs then batch-fetch full details.
    """
    # Build the time window filter
    since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    finding_criteria = {
        "Criterion": {
            # GreaterThanOrEqual for severity
            "severity": {
                "Gte": int(severity_threshold)
            },
            # UpdatedAt within the time window
            "updatedAt": {
                "Gte": int(since.timestamp() * 1000)  # milliseconds
            }
        }
    }

    print(f"[guardduty] Fetching findings since {since_str} "
          f"with severity >= {severity_threshold}")

    paginator = client.get_paginator("list_findings")
    finding_ids = []

    for page in paginator.paginate(
        DetectorId=detector_id,
        FindingCriteria=finding_criteria,
        PaginationConfig={"MaxItems": max_findings}
    ):
        finding_ids.extend(page.get("FindingIds", []))

    print(f"[guardduty] Found {len(finding_ids)} finding IDs")
    return finding_ids


def fetch_finding_details(
    client,
    detector_id: str,
    finding_ids: list[str]
) -> list[dict]:
    """
    CONCEPT: Batching API calls
    get_findings() accepts a maximum of 50 IDs per call.
    We chunk the list into groups of 50 and make one API
    call per chunk. This is called batching.

    list[start:end] is Python slice notation:
    - ids[0:50]  → first 50
    - ids[50:100] → next 50
    - etc.
    """
    if not finding_ids:
        print("[guardduty] No findings to fetch")
        return []

    findings = []

    # Chunk into groups of 50
    chunk_size = 50
    chunks = [
        finding_ids[i:i + chunk_size]
        for i in range(0, len(finding_ids), chunk_size)
    ]

    print(f"[guardduty] Fetching details in {len(chunks)} batch(es)...")

    for i, chunk in enumerate(chunks, 1):
        response = client.get_findings(
            DetectorId=detector_id,
            FindingIds=chunk
        )
        batch = response.get("Findings", [])
        findings.extend(batch)
        print(f"[guardduty] Batch {i}/{len(chunks)}: got {len(batch)} findings")

    print(f"[guardduty] Total findings fetched: {len(findings)}")
    return findings


def fetch_guardduty_findings(
    region:             str   = "eu-central-1",
    severity_threshold: float = 4.0,
    hours_back:         int   = 24,
    max_findings:       int   = 50
) -> list[dict]:
    """
    Main entry point: returns a list of raw GuardDuty finding
    dicts in the same schema as mock_alerts.json.

    The normalizer accepts this output directly — no changes needed.
    """
    client      = boto3.client("guardduty", region_name=region)
    detector_id = get_detector_id(region)
    finding_ids = list_finding_ids(
        client, detector_id,
        severity_threshold=severity_threshold,
        hours_back=hours_back,
        max_findings=max_findings
    )
    findings = fetch_finding_details(client, detector_id, finding_ids)
    return findings


# ── Smoke test ────────────────────────────────────────────────
if __name__ == "__main__":
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print("\n[bold]Fetching live GuardDuty findings...[/bold]\n")

    findings = fetch_guardduty_findings(
        region="eu-north-1",
        severity_threshold=1.0,   # low threshold to catch anything in lab
        hours_back=168,           # last 7 days for lab environment
        max_findings=20
    )

    if not findings:
        console.print(
            "[yellow]No findings returned.[/yellow]\n"
            "This is normal for a quiet lab — GuardDuty only fires on "
            "real or simulated threats.\n"
            "We'll generate sample findings next."
        )
    else:
        table = Table(title=f"Live GuardDuty Findings ({len(findings)})",
                      show_lines=True)
        table.add_column("Severity", width=10)
        table.add_column("Type",     width=40)
        table.add_column("Resource", width=25)
        table.add_column("Region",   width=15)

        sev_colors = {
            "High":     "orange3",
            "Critical": "red",
            "Medium":   "yellow",
            "Low":      "green"
        }

        for f in findings:
            sev   = f.get("Severity", 0)
            stype = f.get("Type", "Unknown")
            res   = f.get("Resource", {})
            rtype = res.get("ResourceType", "?")
            color = "white"
            label = "LOW"

            if sev >= 9:   label, color = "CRITICAL", "red"
            elif sev >= 7: label, color = "HIGH",     "orange3"
            elif sev >= 4: label, color = "MEDIUM",   "yellow"
            else:          label, color = "LOW",      "green"

            table.add_row(
                f"[{color}]{label}[/{color}]",
                stype,
                rtype,
                f.get("Region", "?")
            )

        console.print(table)

        # Save to file for inspection
        out = Path("ingest/live_findings.json")
        out.write_text(json.dumps(findings, indent=2, default=str))
        console.print(f"\n[dim]Raw findings saved to {out}[/dim]")